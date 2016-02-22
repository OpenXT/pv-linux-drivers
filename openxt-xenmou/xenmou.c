/*
 * XenMou Input Driver, for use with XenClient
 *
 * Copyright (c) 2011 - 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

// #define DEBUG
// #define VERBOSE

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
#define MULTITOUCH
#include <linux/input/mt.h>
#else
#warning This kernel does not support multitouch - such devices will not work.
#endif

#include <linux/kthread.h>


#include "debug.h"

#ifndef CONFIG_PCI
#error "This XenMou driver requires PCI support, but this is not included in the kernel."
#endif

#define UBUNTU  0
#define ANDROID 1

static short hostos =
#ifdef CONFIG_ANDROID
    ANDROID;
#else
    UBUNTU;
#endif

module_param (hostos, short, 0);
MODULE_PARM_DESC (hostos,
                  "Indicate which host OS this module this is for, to enable appropriate tweaks in behavior.  0=Ubuntu, 1=Android.");

#define MODULENAME       "XenMou"
#define DRIVER_DESC      "XenMou input driver, for use with XenClient"
#define XENMOU_VENDOR    0x5853
#define XENMOU_ID        0xc110

#define XENMAGIC         0x584D4F55
#define XENREV           0x2
#define XENMOUDRIVERREV  0x1

#define XENCONTROLOFFS   0x100
#define XENEVENTOFFS     0x1000

#define XENMOU_NAME      "XenMou"

#define XENMOU_PAGESIZE  4096

#define ABS_WORDS 2
#define REL_WORDS 1
#define KEY_WORDS 3
#define KEY_START 0x100

#define MAX_SLOTS 64
#define EV_DEV    0x6
#define DEV_SET   0x1
#define DEV_CONF  0x2
#define DEV_RESET 0x3

struct XenMou_version
{
    u32 magic;
    u32 revision;
} __attribute__ ((__packed__));

struct XenMou_control
{
    u32 control;
    u32 eventSize;
    u32 event_npages;
    u32 acceleration;
    u32 isr;
    u32 conf_size;
    u32 client_rev;
} __attribute__ ((__packed__));

struct XenMou_eventBuffer
{
    u32 readOffs;
    u32 writeOffs;
} __attribute__ ((__packed__));


struct device_property
{
    char name[40];
    uint32_t evbits;
    uint32_t absbits[ABS_WORDS];
    uint32_t relbits[REL_WORDS];
    uint32_t btnbits[KEY_WORDS];
};

struct XenMou_event2
{
    u16 type;
    u16 code;
    u32 value;
} __attribute__ ((__packed__));

typedef struct
{
    struct device_property *dev_prop;
    struct input_dev *dev;
    uint8_t reset;
    uint8_t add;
} xm_device;

static struct XenMou_DriverInfo
{
    void *base;
    struct pci_dev *dev;
    struct XenMou_control *control;
    struct XenMou_eventBuffer *buffer;
    struct device_property *config;
    u32 npages;

    xm_device xm_devices[MAX_SLOTS];
    int max_slot;
    struct task_struct *thread;

} DriverInfo;

struct pci_dev;

int xenmou_init_one (struct pci_dev *dev, const struct pci_device_id *id);
static void xenmou_remove_one (struct pci_dev *pdev);
static irqreturn_t irq_handler (int irq, void *info);
static void destroy_device (struct XenMou_DriverInfo *dr, int slot);
static int xenmou_thread_fn (void *data);


MODULE_DEVICE_TABLE (pci, xenmou_pci_tbl);

static const struct pci_device_id xenmou_pci_tbl[]
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinitdata
#endif
= {
    {PCI_DEVICE (XENMOU_VENDOR, XENMOU_ID)},
    {0,}                        /* 0 terminated list. */
};

static int suspend (struct pci_dev *dev, pm_message_t state)
{
    DEBUG_MSG ("XenMou: Suspending!\n");
    xenmou_remove_one (dev);
    return 0;
}

static int resume (struct pci_dev *dev)
{
    DEBUG_MSG ("XenMou: Resumeing!\n");
    xenmou_init_one (dev, NULL);
    return 0;
}

static struct pci_driver xenmou_driver = {
    .name = XENMOU_NAME,
    .probe = xenmou_init_one,
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0) )
    .remove = __devexit_p (xenmou_remove_one),
#else
    .remove = xenmou_remove_one,
#endif
    .id_table = xenmou_pci_tbl,
    .suspend = suspend,
    .resume = resume
};

#define LONG_BITS (sizeof(long) * 8)
#define NBITS(x) (((x) + LONG_BITS - 1) / LONG_BITS)

int create_device (struct XenMou_DriverInfo *dr, int slot)
{
    char tempname[128];
    char *string;
    xm_device *xd = &dr->xm_devices[slot];
    struct input_dev *d = input_allocate_device ();
    int ret;
    unsigned long *btnbit;

    {
    char tmpabsbits[16 + 6] = "";
    char tmprelbits[8 + 6] = "";
    char tmpbtnbits[8*3 + 2 + 6] = "";

    int ev = xd->dev_prop->evbits;    

    if (ev & (1 << EV_ABS)) 
	snprintf(tmpabsbits, sizeof(tmpabsbits), " a 0x%016llX", *((uint64_t *) xd->dev_prop->absbits));

    if (ev & (1 << EV_REL))
        snprintf(tmprelbits, sizeof(tmprelbits), " r 0x%08X.\n", *xd->dev_prop->relbits);

    if (ev & (1 << EV_KEY))
        snprintf(tmpbtnbits, sizeof(tmpbtnbits), " b 0x%08X %08X %08X", xd->dev_prop->btnbits[2],
								        xd->dev_prop->btnbits[1],
                                                         	        xd->dev_prop->btnbits[0]);

    printk (KERN_INFO "XenMou: name %s, ev_bits 0x%x%s%s%s.\n", xd->dev_prop->name, ev,
   								tmpabsbits, tmprelbits, tmpbtnbits);
    }

    d->phys = NULL;
    d->name = NULL;

    /* physical */

    snprintf (tempname, sizeof (tempname), "pci-%s/input%d", pci_name (dr->dev), slot);

    string = NULL;
    string = kmalloc (strlen (tempname) + 1, GFP_ATOMIC);
    if (!string)
    {
        printk (KERN_INFO "XenMou: Failed to allocate phys string!\n");
        destroy_device (dr, slot);
        return -1;
    }
    strcpy (string, tempname);
    d->phys = string;
    string = NULL;

    /* name */
    snprintf (tempname, sizeof (tempname), "XenMou: %s", xd->dev_prop->name);
    string = kmalloc (strlen (tempname) + 1, GFP_ATOMIC);
    if (!string)
    {
        printk (KERN_INFO "XenMou: Failed to allocate phys string!\n");
        destroy_device (dr, slot);
        return -1;
    }

    strcpy (string, tempname);
    d->name = string;

    d->id.product = XENMOU_ID;
    d->id.bustype = BUS_PCI;
    d->id.vendor = XENMOU_VENDOR;
    d->id.version = XENMOUDRIVERREV;
    d->dev.parent = &dr->dev->dev;

    xd->dev = d;

    d->evbit[0] = xd->dev_prop->evbits;
    d->relbit[0] = xd->dev_prop->relbits[0];
    memcpy (d->absbit, xd->dev_prop->absbits, sizeof (xd->dev_prop->absbits));

    btnbit = &(d->keybit[NBITS (BTN_MISC)]);

    memcpy (btnbit, xd->dev_prop->btnbits, sizeof (xd->dev_prop->btnbits));

#ifdef MULTITOUCH
    if (test_bit (ABS_MT_SLOT, d->absbit))
    {
        DEBUG_MSG ("XenMou: Multitouch device!\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
        input_mt_init_slots (d, 8, 0);
#else
        input_mt_init_slots (d, 8);
#endif
        input_set_abs_params (d, ABS_MT_TOOL_TYPE, 0, MT_TOOL_MAX, 0, 0);
        if (hostos == UBUNTU)
        {
            __set_bit (BTN_TOUCH, d->keybit);
            __set_bit (EV_KEY, d->evbit);
        }
    }

    if (test_bit (ABS_MT_POSITION_X, d->absbit))
    {
        input_set_abs_params (d, ABS_MT_POSITION_X, 0, (0x7fff) >> 0, 0, 0);
        input_set_abs_params (d, ABS_X, 0, (0x7fff) >> 0, 0, 0);
    }

    if (test_bit (ABS_MT_POSITION_Y, d->absbit))
    {
        input_set_abs_params (d, ABS_MT_POSITION_Y, 0, (0x7fff) >> 0, 0, 0);
        input_set_abs_params (d, ABS_Y, 0, (0x7fff) >> 0, 0, 0);
    }
#endif


    if (test_bit (ABS_X, d->absbit))
        input_set_abs_params (d, ABS_X, 0, 0x7fff, 0, 0);
    if (test_bit (ABS_Y, d->absbit))
        input_set_abs_params (d, ABS_Y, 0, 0x7fff, 0, 0);
    if (test_bit (ABS_PRESSURE, d->absbit))
        input_set_abs_params (d, ABS_PRESSURE, 0, 0xff, 0, 0);

    ret = input_register_device (d);
    if (ret)
    {
        printk (KERN_INFO "Error: Could not register input device on slot %d: Error %x\n", slot, ret);
        destroy_device (dr, slot);
        return -1;
    }

    return 0;
}


void destroy_device (struct XenMou_DriverInfo *dr, int slot)
{
    xm_device *xd = &dr->xm_devices[slot];
    struct input_dev *dev = xd->dev;
    const char *phys = xd->dev->phys;
    const char *name = xd->dev->name;
    xd->dev = NULL;
    input_unregister_device (dev);
    kfree (phys);
    kfree (name);
}


int scan_devs (struct XenMou_DriverInfo *dr)
{

    xm_device *dl = dr->xm_devices;
    int slot;
    DEBUG_MSG ("XenMou: Scanning for devices.\n");

    for (slot = 0; slot <= dr->max_slot; slot++)
    {
        xm_device *xd = &dl[slot];
        if (xd->reset)
        {
            if (xd->dev)
                destroy_device (dr, slot);
            xd->reset = 0;
        }
        if (xd->add)
        {
            if ((!xd->dev) && xd->dev_prop->evbits)
                create_device (dr, slot);
            else
                DEBUG_MSG ("XenMou: Request to add device, but dev= 0x%lx, evbits=0x%x.\n",(unsigned long) xd->dev,
                           xd->dev_prop->evbits);
            xd->add = 0;
        }
    }
    return kthread_should_stop ();
}



int xenmou_init_one (struct pci_dev *dev, const struct pci_device_id *id)
{
    int ret = 0;
    struct XenMou_version *version;
    int i;
    int stride;
    uint8_t *dev_prop;
    uint32_t rev;
    uint32_t temp;

#ifndef MULTITOUCH
    printk (KERN_INFO "XenMou: This kernel does not support multitouch - such devices will not work.");
#endif

    if (DriverInfo.dev)
    {
        printk (KERN_INFO "XenMou: Driver only supports one PCI device.");
        return -EBUSY;
    }

    ret = (pci_enable_device (dev));
    if (ret)
    {
        printk (KERN_INFO "XenMou Error: Could not enable device.");
        return ret;
    }

    ret = pci_request_regions (dev, MODULENAME);
    if (ret < 0)
    {
        printk (KERN_ERR "XenMou Error: pci_request_regions failed!\n");
        return ret;
    }

    DriverInfo.dev = dev;
    DriverInfo.base = ioremap_nocache (pci_resource_start (dev, 0), pci_resource_len (dev, 0));

    version = (struct XenMou_version *) DriverInfo.base;
    DriverInfo.control = (struct XenMou_control *) ((unsigned char*) DriverInfo.base + XENCONTROLOFFS);
    DriverInfo.buffer = (struct XenMou_eventBuffer *) ((unsigned char*) DriverInfo.base + XENEVENTOFFS);

    DriverInfo.npages = ioread32(&DriverInfo.control->event_npages);

    temp = ioread32(&version->magic);
    if (temp != XENMAGIC)
    {
        printk (KERN_INFO
                "XenMou Error: Incorrect XenMou Magic number. Value is %x. "
                "This means this XenMou module cannot see its backend, and hence cannot operate.\n", temp);
        goto exit;
    }

    iowrite32(XENREV, &DriverInfo.control->client_rev);
    barrier();

    rev = ioread32(&version->revision);
    if (rev != XENREV)
        printk (KERN_INFO
                "XenMou NOTICE: This module, (version %x) is not at the same version as backend (version %x)\n",
                XENREV,rev);

    temp = ioread32(&DriverInfo.control->client_rev);
    if (DriverInfo.control->client_rev != XENREV)
    {
        printk (KERN_INFO
                "XenMou ERROR: This module is not supported by the backend! (0x%x)\n", DriverInfo.control->client_rev);
        goto exit;
    }

    stride = ioread32(&DriverInfo.control->conf_size);
    dev_prop = (uint8_t *) ((unsigned char*) DriverInfo.base + XENEVENTOFFS + (DriverInfo.npages * XENMOU_PAGESIZE));

// Inishalize slots;
    for (i = 0; i < MAX_SLOTS; i++)
    {
        DriverInfo.xm_devices[i].dev = NULL;
        DriverInfo.xm_devices[i].dev_prop = (struct device_property *) dev_prop;
        DriverInfo.xm_devices[i].reset = 0;
        DriverInfo.xm_devices[i].add = 0;
        dev_prop += stride;
    }
    DriverInfo.max_slot = 0;

    DriverInfo.thread = kthread_run (xenmou_thread_fn, &DriverInfo, "XenMou");
    if (IS_ERR (DriverInfo.thread))
    {
        printk (KERN_INFO "XenMou Error: Could not create thead!\n");
        goto exit;
    }

    ret = request_irq (dev->irq, irq_handler, IRQF_SHARED | IRQF_DISABLED, XENMOU_NAME, &DriverInfo);

    iowrite32(0x3, &DriverInfo.control->control);
    printk (KERN_INFO "XenMou (v%d) inishalised ok. OS = %d\n", rev, hostos);

    return 0;

  exit:
    iounmap (DriverInfo.base);
    pci_release_regions (dev);
    return -ENODEV;
}

static void process_events (struct XenMou_DriverInfo *inf, int in_int);

static DECLARE_WAIT_QUEUE_HEAD (wait_queue);


int xenmou_thread_fn (void *data)
{
    struct XenMou_DriverInfo *inf = (struct XenMou_DriverInfo *) data;

    DEBUG_MSG ("XenMou: xenmou_thread_fn!\n");

    wait_event_interruptible (wait_queue, kthread_should_stop () || scan_devs (inf));

    DEBUG_MSG ("XenMou: xenmou_thread_fn exiting!\n");
    return 0;
}


static void ack_int (struct XenMou_DriverInfo *inf)
{
    int mask = ioread32(&inf->control->isr) & 0x1;
    iowrite32(mask, &inf->control->isr);
}


static irqreturn_t irq_handler (int irq, void *info)
{
    struct XenMou_DriverInfo *inf = (struct XenMou_DriverInfo *) info;

    if (!(ioread32(&inf->control->isr) & 0x1))
        {
        return IRQ_NONE;
        }
    process_events ((struct XenMou_DriverInfo *) info, true);
    ack_int (inf);
    return IRQ_HANDLED;

}

static void process_events (struct XenMou_DriverInfo *inf, int in_int)
{
    static int interface = -1;
    static struct input_dev *idev = NULL;

    u32 *readptr = &inf->buffer->readOffs;
    u32 *writeptr = &inf->buffer->writeOffs;
    u32 recsize = 8;

    unsigned long bufferstart = ((unsigned long) inf->base) + XENEVENTOFFS + recsize;
    u32 nevents = (inf->npages * (XENMOU_PAGESIZE / recsize)) - 2;
    u32 temp;
    struct XenMou_event2 *data_ptr;
    struct XenMou_event2 pd;
    u32 read;

    read = ioread32(readptr);

    DEBUG_INIT while (read != ioread32(writeptr))
    {
        data_ptr = (struct XenMou_event2 *) (bufferstart + read * recsize);
        memcpy_fromio(&pd, data_ptr, recsize);


        if (pd.type == EV_DEV)
        {
            switch (pd.code)
            {
            case DEV_SET:
                DEBUG_DEV_SET interface = pd.value;
                idev = NULL;
                break;
            case DEV_CONF:
                DEBUG_MSG ("XenMou: Recieved new config for %d\n", pd.value);
                if (pd.value < MAX_SLOTS)
                {
                    if (pd.value > inf->max_slot)
                        inf->max_slot = pd.value;
                    inf->xm_devices[pd.value].add = 1;
                    DEBUG_MSG ("XenMou: Marking add for it\n");
                    wake_up (&wait_queue);
                }
                break;
            case DEV_RESET:
                DEBUG_MSG ("XenMou: Recieved reset %d\n", pd.value);
                if (pd.value == 0xFF)
                {
                    DEBUG_MSG ("XenMou: Recieved reset for all\n");
                    for (temp = 0; temp <= inf->max_slot; temp++)
                        inf->xm_devices[temp].reset = 1;
                }
                else if (pd.value <= inf->max_slot)
                {
                    inf->xm_devices[pd.value].reset = 1;
                    DEBUG_MSG ("XenMou: Marking reset for it\n");
                }
                wake_up (&wait_queue);
                break;
            default:
                DEBUG_MSG ("XenMou: Unexpected EV_DEV code %d\n", pd.code);

            } /*switch */
        }
        else  /*if not EV_DEV */
        {
        if (!idev && interface >= 0)
        {
                    if ((interface <= DriverInfo.max_slot) && (DriverInfo.xm_devices[interface].dev))
                    {
                    idev = DriverInfo.xm_devices[interface].dev;
                    DEBUG_SWITCH_DEV
            }
            }
            if (idev)
            {
#ifdef MULTITOUCH
                if ((pd.type == EV_ABS) && (pd.code == ABS_MT_TRACKING_ID))        // MT tracking IDs should be generated locally
                {
                    input_mt_report_slot_state (idev, MT_TOOL_FINGER, (pd.value != -1));
                    DEBUG_PACKET
                }
                else
#endif
                {
#ifndef DEBUG
                    input_event (idev, pd.type, pd.code, pd.value);
                }
#else
                    DEBUG_AND_input_event        /*
                }                                brace in macro! */
#endif
            } /*if idev */
        }     /* end EV_DEV */
    read = (read == nevents) ? 0 : read + 1;
    iowrite32(read,readptr);
    }   /* while */
}       /* process events  - function end */



static void xenmou_remove_one (struct pci_dev *pdev)
{
    int i;
    iowrite32(0x0, &DriverInfo.control->control);

    free_irq (DriverInfo.dev->irq, &DriverInfo);
    DriverInfo.dev = NULL;
    if (DriverInfo.thread)
        kthread_stop (DriverInfo.thread);
    iounmap (DriverInfo.base);
    pci_release_regions (pdev);

    for (i = 0; i < MAX_SLOTS; i++)
        if (DriverInfo.xm_devices[i].dev)
        {
            destroy_device (&DriverInfo, i);
        }

    printk (KERN_INFO "XenMou unloaded.\n");
}


__init int init_module (void)
{
    int pci_rc;

    DriverInfo.dev = NULL;

    pci_rc = pci_register_driver (&xenmou_driver);

    return (pci_rc < 0) ? pci_rc : 0;
}

__exit void cleanup_module (void)
{
    pci_unregister_driver (&xenmou_driver);
}

MODULE_LICENSE ("GPL v2");
