/******************************************************************************
 * vusb.c
 *
 * OpenXT vUSB frontend driver
 *
 * Copyright (c) 2013 Julien Grall
 * Copyright (c) 2011 Thomas Horsten
 * Copyright (c) 2013 OpenXT Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/***
 *** TODO
 *** - Modify thread handling
 *** - Add branch prediction
 *** - Send cancel URB command if needed
 *** - Management support
 *** - Devices are not kept accross suspend/hibernate (vusb daemon issue)
 *** - Reorganize the code
 ***/

#include <linux/mm.h>
#include <linux/version.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/kthread.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) )
#include <linux/aio.h>
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35) || (defined(RHEL_RELEASE_CODE)) )
#include <linux/usb/hcd.h>
#else
#include <linux/old-core-hcd.h>
#endif

#include <linux/v4v_dev.h>

#define VUSB_MAX_PACKET_SIZE 1024*256

#define DRIVER_DESC	"OpenXT USB Host Controller"
#define DRIVER_VERSION  "1.0.0"

#define POWER_BUDGET	5000 /* mA */

#define D_V4V1 (1 << 0)
#define D_V4V2 (1 << 1)
#define D_URB1 (1 << 2)
#define D_URB2 (1 << 3)
#define D_STATE (1 << 4)
#define D_PORT1 (1 << 5)
#define D_PORT2 (1 << 6)
#define D_CTRL (1 << 8)
#define D_MISC (1 << 9)
#define D_WARN (1 << 10) /* only debugging warn */
#define D_PM (1 << 11)

#define DEBUGMASK (D_STATE | D_PORT1 | D_URB1 | D_PM)

// Enable debug
// #define VUSB_DEBUG

#ifdef VUSB_DEBUG
#  define dprintk(mask, args...)					\
	do {								\
		if (DEBUGMASK & mask)					\
			printk(KERN_DEBUG "vusb: "args);		\
	} while (0)

#  define dprint_hex_dump(mask, args...)				\
	do {								\
		if (DEBUGMASK & mask)					\
			print_hex_dump(KERN_DEBUG, "vusb: "args);	\
	} while (0)
#else
#  define dprintk(args...) do {} while (0)
#  define dprint_hex_dump(args...) do {} while (0)
#endif

#define eprintk(args...) printk(KERN_ERR "vusb: "args)
#define wprintk(args...) printk(KERN_WARNING "vusb: "args)
#define iprintk(args...) printk(KERN_INFO "vusb: "args)

/* How many ports on the root hub */
#ifdef VUSB_DEBUG
# define VUSB_PORTS	2
#else
# define VUSB_PORTS    USB_MAXCHILDREN
#endif

/* Status codes */
#define VUSB_URB_STATUS_SUCCESS            0x00000000
#define VUSB_URB_STATUS_FAILURE            0xFFFFFFFF

/* Command flag aliases for USB kernel URB states */
#define VUSB_URB_DIRECTION_IN      0x0001
#define VUSB_URB_SHORT_OK          0x0002
#define VUSB_URB_ISO_TRANSFER_ASAP 0x0004

/* V4V port and domid used to connect to vusb daemon */
#define VUSB_V4V_PORT 3136200
#define VUSB_V4V_DOMID 0

static const char	driver_name [] = "vusb_hcd";
static const char	driver_desc [] = DRIVER_DESC;

/* Port are numbered from 1 in linux */
#define vusb_device_by_port(v, port) (&(v)->device[(port) - 1])
#define vusb_check_port(req, index)					\
do {								\
	if ((index) < 1 || (index) > VUSB_PORTS) {		\
		wprintk(req" with invalid port %u", (index));	\
		retval = -EPIPE;				\
		break;						\
	}							\
} while (0)

/* USB HCD */

enum vusb_rh_state {
	VUSB_RH_RESET,
	VUSB_RH_SUSPENDED,
	VUSB_RH_RUNNING
};

/* Possible state of an urbp */
enum vusb_urbp_state {
	VUSB_URBP_NEW,
	VUSB_URBP_SENT,
	VUSB_URBP_DONE,
	VUSB_URBP_DROP, /* Only here for debug purpose, it's same as done */
	VUSB_URBP_CANCEL,
};

struct urbp {
	struct urb		*urb;
	enum vusb_urbp_state	state;
	u16                     handle;
	struct list_head	urbp_list;
	int                     port;
};

struct vusb_device {
	unsigned              present:1;
	unsigned              reset:2;
	u16                   deviceid;
	u32                   port_status;
	/* TODO: is it usefull? It's only set during SetAddress control command and never used */
	u16                   address;
	/**
	 * Use only for debugging. It's use full to know the index of the
	 * structure in device
	 * */
	u16					  port;

	enum usb_device_speed speed;
	struct usb_device     *udev;
};

enum vusb_state {
	VUSB_INACTIVE,
	VUSB_WAIT_BIND_RESPONSE,
	VUSB_RUNNING,
};

struct vusb {
	struct usb_device               *dev;

	spinlock_t			lock;

	enum vusb_rh_state		rh_state;
	struct vusb_device		device[VUSB_PORTS];
	struct list_head		vdev_list;
	unsigned			resuming:1;
	/*
	 * Update hub can't be done in critical section.
	 * Is the driver need to update the hub?
	 */
	unsigned			poll:1;
	unsigned long			re_timeout;
	struct list_head                urbp_list;
	u16                   		urb_handle;
	/* File operation for the v4v connection */
	struct file 			*fp;
	/* Main thread */
	struct task_struct 		*kthread;
	enum vusb_state		state;
};

static struct platform_device *the_vusb_hcd_pdev;

static u8 *pbuf = NULL;

/* Forward declarations */
static int vusb_open(struct vusb *v);
static void vusb_close(struct vusb *v);
static int vusb_threadfunc(void *data);
static void vusb_urbp_release(struct vusb *v,
			struct vusb_device *dev,
			struct urbp *urbp);

static inline struct vusb*
hcd_to_vusb(struct usb_hcd *hcd)
{
	return (struct vusb *)(hcd->hcd_priv);
}

static inline struct usb_hcd*
vusb_to_hcd (struct vusb *v)
{
	return container_of((void *) v, struct usb_hcd, hcd_priv);
}

static inline struct device*
vusb_dev (struct vusb *v)
{
	return vusb_to_hcd(v)->self.controller;
}

#ifdef VUSB_DEBUG

/* Convert Root Hub state in a string */
static const char*
vusb_rhstate_to_string(const struct vusb *v)
{
	switch (v->rh_state) {
	case VUSB_RH_RESET:
		return "RESET";
	case VUSB_RH_SUSPENDED:
		return "SUSPENDED";
	case VUSB_RH_RUNNING:
		return "RUNNING";
	default:
		return "Unknown";
	}
}

/* Convert urb pipe type to string */
static const char *
vusb_pipe_to_string(struct urb *urb)
{

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_ISOCHRONOUS:
		return "ISOCHRONOUS";
	case PIPE_CONTROL:
		return "CONTROL";
	case PIPE_INTERRUPT:
		return "INTERRUPT";
	case PIPE_BULK:
		return "BULK";
	default:
		return "Unknown";
	}
}

/* Convert urbp state to string */
static const char *
vusb_state_to_string(const struct urbp *urbp)
{
	switch (urbp->state) {
	case VUSB_URBP_NEW:
		return "NEW";
	case VUSB_URBP_SENT:
		return "SENT";
	case VUSB_URBP_DONE:
		return "DONE";
	case VUSB_URBP_DROP:
		return "DROP";
	case VUSB_URBP_CANCEL:
		return "CANCEL";
	default:
		return "unknow";
	}
}

#endif /* VUSB_DEBUG */

/* Helper to create the worker */
static int
vusb_worker_start(struct vusb *v)
{
	int ret = 0;
	u16 i = 0;

	dprintk(D_PM, "Start the worker\n");

	/* Initialize ports */
	for (i = 0; i < VUSB_PORTS; i++) {
		v->device[i].port = i + 1;
		v->device[i].present = 0;
	}

	v->rh_state = VUSB_INACTIVE;

	/* Open v4v connection */
	ret = vusb_open(v);
	if (ret != 0)
		goto err_conn;

	/* Create the main thread */
	v->kthread = kthread_run(vusb_threadfunc, v, "vusb");
	if (IS_ERR(v->kthread)) {
		ret = PTR_ERR(v->kthread);
		eprintk("unable to start the thread: %d", ret);
		vusb_close(v);
		goto err_thread;
	}

	return 0;
err_thread:
	vusb_close(v);
err_conn:
	return ret;
}

/* Helper to cleanup data associated to the worker */
static void
vusb_worker_cleanup(struct vusb *v)
{
	struct urbp *urbp;
	struct urbp *next;
	u16 i = 0;
	unsigned long flags;

	dprintk(D_PM, "Clean up the worker\n");

	vusb_close(v);

	spin_lock_irqsave(&v->lock, flags);
	v->rh_state = VUSB_INACTIVE;

	list_for_each_entry_safe(urbp, next, &v->urbp_list, urbp_list) {
		struct vusb_device *dev;

		dev = vusb_device_by_port(v, urbp->port);
		urbp->urb->status = -ESHUTDOWN;
		vusb_urbp_release(v, dev, urbp);
	}

	/* Unplug all USB devices */
	for (i = 0; i < VUSB_PORTS; i++) {
		v->device[i].port = i + 1;
		v->device[i].present = 0;
	}

	spin_unlock_irqrestore(&v->lock, flags);
}

/*
 * Helper to stop the worker
 * FIXME: there is a race condition with send_sig and kthread_stop
 */
static inline void
vusb_worker_stop(struct vusb *v)
{
	dprintk(D_PM, "Stop the worker\n");

	send_sig(SIGINT, v->kthread, 0); /* To left the function read */
	kthread_stop(v->kthread);
}

/*
 * Notify the worker that there is a new task
 * FIXME: I think the best solution is to have
 * a pending queue
 */
static inline void
vusb_worker_notify(struct vusb *v)
{
	send_sig(SIGINT, v->kthread, 0);
}

/* Dump the URBp list */
static inline void
vusb_urbp_list_dump(const struct vusb *v, const char *fn)
{
	const struct urbp *urbp;

	dprintk(D_URB2, "===== Current URB List in %s =====\n", fn);
	list_for_each_entry(urbp, &v->urbp_list, urbp_list) {
		dprintk(D_URB1, "URB handle 0x%x port %u device %u\n",
			urbp->handle, urbp->port,
			vusb_device_by_port(v, urbp->port)->deviceid);
	}
	dprintk(D_URB2, "===== End URB List in %s ====\n", fn);
}

#ifdef VUSB_DEBUG
/* Dump URBp */
static inline void
vusb_urbp_dump(const struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	unsigned int type;

	type = usb_pipetype(urb->pipe);

	iprintk("urb handle: 0x%x state: %s status: %d pipe: %s(%u)\n",
		urbp->handle, vusb_state_to_string(urbp),
		urb->status, vusb_pipe_to_string(urb), type);
	iprintk("Device: %u Endpoint: %u In: %u\n",
		usb_pipedevice(urb->pipe),
		usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));
}
#endif /* VUSB_DEBUG */

static inline u16 usb_speed_to_port_stat(enum usb_device_speed speed)
{
	switch (speed) {
	case USB_SPEED_HIGH:
		return USB_PORT_STAT_HIGH_SPEED;
	case USB_SPEED_LOW:
		return USB_PORT_STAT_LOW_SPEED;
	case USB_SPEED_FULL:
	default:
		return 0;
	}
}

static void
set_link_state (struct vusb *v, struct vusb_device *dev)
{
	u32 newstatus, diff;

	newstatus = dev->port_status;
	dprintk(D_STATE, "SLS: Port index %u status 0x%08x\n",
			dev->port, newstatus);

	if (dev->present) {
		newstatus |= (USB_PORT_STAT_CONNECTION) |
					usb_speed_to_port_stat(dev->speed);
	} else {
		newstatus &= ~(USB_PORT_STAT_CONNECTION |
					USB_PORT_STAT_LOW_SPEED |
					USB_PORT_STAT_HIGH_SPEED |
					USB_PORT_STAT_ENABLE |
					USB_PORT_STAT_SUSPEND);
	}
	if ((newstatus & USB_PORT_STAT_POWER) == 0) {
		newstatus &= ~(USB_PORT_STAT_CONNECTION |
					USB_PORT_STAT_LOW_SPEED |
					USB_PORT_STAT_HIGH_SPEED |
					USB_PORT_STAT_SUSPEND);
	}
	diff = dev->port_status ^ newstatus;

	if ((newstatus & USB_PORT_STAT_POWER) &&
	    (diff & USB_PORT_STAT_CONNECTION)) {
		newstatus |= (USB_PORT_STAT_C_CONNECTION << 16);
		dprintk(D_STATE, "Port %u connection state changed: %08x\n",
				dev->port, newstatus);
	}

	dev->port_status = newstatus;
}

/* SetFeaturePort(PORT_RESET) */
static void
vusb_port_reset(struct vusb *v, struct vusb_device *dev)
{
	printk(KERN_DEBUG"vusb: port reset %u 0x%08x",
		   dev->port, dev->port_status);

	dev->port_status |= USB_PORT_STAT_ENABLE | USB_PORT_STAT_POWER;

	dev->reset = 1;

	vusb_worker_notify(v);
}

static void
set_port_feature(struct vusb *v, struct vusb_device *dev, u16 val)
{
	if (!dev)
		return;

	switch (val) {
	case USB_PORT_FEAT_INDICATOR:
	case USB_PORT_FEAT_SUSPEND:
		// Ignored now
		break;

	case USB_PORT_FEAT_POWER:
		dev->port_status |= USB_PORT_STAT_POWER;
		break;
	case USB_PORT_FEAT_RESET:
		vusb_port_reset(v, dev);
		break;
	case USB_PORT_FEAT_C_CONNECTION:
	case USB_PORT_FEAT_C_RESET:
	case USB_PORT_FEAT_C_ENABLE:
	case USB_PORT_FEAT_C_SUSPEND:
	case USB_PORT_FEAT_C_OVER_CURRENT:
		dev->port_status &= ~(1 << val);
		break;

	default:
		/* No change needed */
		return;
	}
	set_link_state(v, dev);
}

static void
clear_port_feature(struct vusb *v, struct vusb_device *dev, u16 val)
{
	switch (val) {
	case USB_PORT_FEAT_INDICATOR:
	case USB_PORT_FEAT_SUSPEND:
		// Ignored now
		break;

	case USB_PORT_FEAT_ENABLE:
		dev->port_status &= ~USB_PORT_STAT_ENABLE;
		set_link_state(v, dev);
		break;

	case USB_PORT_FEAT_POWER:
		dev->port_status &= ~(USB_PORT_STAT_POWER | USB_PORT_STAT_ENABLE);
		set_link_state(v, dev);
		break;

	case USB_PORT_FEAT_C_CONNECTION:
	case USB_PORT_FEAT_C_RESET:
	case USB_PORT_FEAT_C_ENABLE:
	case USB_PORT_FEAT_C_SUSPEND:
	case USB_PORT_FEAT_C_OVER_CURRENT:
		dprintk(D_PORT1, "Clear bit %d, old 0x%08x mask 0x%08x new 0x%08x\n",
				val, dev->port_status, ~(1 << val),
				dev->port_status & ~(1 << val));
		dev->port_status &= ~(1 << val);
		break;

	default:
		/* No change needed */
		return;
	}
}

/* HCD start */
static int
vusb_start (struct usb_hcd *hcd)
{
	struct vusb *v = hcd_to_vusb(hcd);

	iprintk("XEN HCD start\n");

	dprintk(D_MISC, ">vusb_start\n");

	v->rh_state = VUSB_RH_RUNNING;

	hcd->power_budget = POWER_BUDGET;
	hcd->state = HC_STATE_RUNNING;
	hcd->uses_new_polling = 1;

	dprintk(D_MISC, "<vusb_start 0\n");

	return 0;
}

/* HCD stop */
static void vusb_stop (struct usb_hcd *hcd)
{
	struct vusb		*v;

	iprintk("XEN HCD stop\n");

	dprintk(D_MISC, ">vusb_stop\n");

	v = hcd_to_vusb (hcd);

	hcd->state = HC_STATE_HALT;
	/* TODO: remove all URBs */

	//device_remove_file (dummy_dev(dum), &dev_attr_urbs);
	dev_info (vusb_dev(v), "stopped\n");
	dprintk(D_MISC, "<vusb_stop\n");
}

/* Get a uniq URB handle */
static u16
vusb_get_urb_handle(struct vusb *v)
{
	v->urb_handle += 1;

	if (v->urb_handle >= 0xfff0)
		/* reset to 0 we never have lots URB in the list */
		v->urb_handle = 0;

	return v->urb_handle;
}

/*
 * Notify USB stack that the URB is finished and release it
 * The lock is already taken
 */
static void
vusb_urbp_release(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp)
{
	struct urb *urb = urbp->urb;

#ifdef VUSB_DEBUG
	if (urb->status)
		vusb_urbp_dump(v, urbp);
#endif

	dprintk(D_URB1, "Giveback URB 0x%x status %d length %u\n",
		urbp->handle, urb->status, urb->actual_length);
	list_del(&urbp->urbp_list);
	kfree(urbp);
	usb_hcd_unlink_urb_from_ep(vusb_to_hcd(v), urb);
	/* Unlock the lock before notify the USB stack (could call other cb) */
	spin_unlock(&v->lock);
	usb_hcd_giveback_urb(vusb_to_hcd(v), urb, urb->status);
	spin_lock(&v->lock);
}

/* Retrieve device by device ID */
static struct vusb_device *
vusb_device_by_devid(struct vusb *v, u16 id)
{
	u16 i;

	for (i = 0; i < VUSB_PORTS; i++) {
		struct vusb_device *device = &v->device[i];
		if (device->present && device->deviceid == id)
			return &v->device[i];
	}

	return NULL;
}

static int
vusb_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct vusb *v;
	unsigned long flags;
	struct urbp *urbp;
	const struct vusb_device *dev;

	int r = -ENOMEM;

	dprintk(D_MISC, ">vusb_urb_enqueue\n");

	v = hcd_to_vusb (hcd);

	if (!urb->transfer_buffer && urb->transfer_buffer_length)
		return -EINVAL;

	urbp = kmalloc (sizeof *urbp, mem_flags);
	if (!urbp)
		return -ENOMEM;

	urbp->state = VUSB_URBP_NEW;
	/* Port numbered from 1 */
	urbp->port = urb->dev->portnum;
	urbp->urb = urb;
	spin_lock_irqsave (&v->lock, flags);
	dev = vusb_device_by_port(v, urbp->port);
	/* Allocate a handle */
	urbp->handle = vusb_get_urb_handle(v);

	if (v->state == VUSB_INACTIVE || !dev->present) {
		dprintk(D_WARN, "Worker is not up\n");
		kfree(urbp);
		r = -ESHUTDOWN;
		goto done;
	}

	r = usb_hcd_link_urb_to_ep(hcd, urb);
	if (r) {
		kfree(urbp);
		goto done;
	}

	list_add_tail(&urbp->urbp_list, &v->urbp_list);
	vusb_worker_notify(v);

done:
	spin_unlock_irqrestore (&v->lock, flags);

	return r;
}

static int
vusb_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct vusb *v;
	unsigned long flags;
	int rc;
	struct urbp *urbp;

	dprintk(D_MISC, "*vusb_urb_dequeue\n");
	v = hcd_to_vusb (hcd);

	spin_lock_irqsave (&v->lock, flags);

	rc = usb_hcd_check_unlink_urb(hcd, urb, status);

	if (rc)
		goto out_dequeue;

	urb->status = status;

	/* Retrieve URBp */
	list_for_each_entry(urbp, &v->urbp_list, urbp_list) {
		if (urbp->urb == urb)
			break;
	}

	if (urbp) {
		urbp->state = VUSB_URBP_CANCEL;
		vusb_worker_notify(v);
	} else
		wprintk("Try do dequeue an unhandle URB\n");

out_dequeue:
	spin_unlock_irqrestore (&v->lock, flags);

	return rc;
}

static int
vusb_get_frame(struct usb_hcd *hcd)
{
	struct timeval	tv;

	dprintk(D_MISC, "*vusb_get_frame\n");
	do_gettimeofday (&tv);

	return tv.tv_usec / 1000;
}

#define PORT_C_MASK \
	((USB_PORT_STAT_C_CONNECTION \
	| USB_PORT_STAT_C_ENABLE \
	| USB_PORT_STAT_C_SUSPEND \
	| USB_PORT_STAT_C_OVERCURRENT \
	| USB_PORT_STAT_C_RESET) << 16)

static int
vusb_hub_status(struct usb_hcd *hcd, char *buf)
{
	struct vusb *v = hcd_to_vusb(hcd);
	unsigned long flags;
        int resume = 0;
	int changed = 0;
	u16 length = 0;
	int	ret = 0;
	u16 i;

	dprintk(D_MISC, ">vusb_hub_status\n");

	/* FIXME: Not sure it's good */
	if (!HCD_HW_ACCESSIBLE(hcd)) {
		wprintk("Hub is not running %u\n", hcd->state);
		dprintk(D_MISC, ">vusb_hub_status 0\n");
		return 0;
	}

	/* Initialize the status to no-change */
	length = 1 + (VUSB_PORTS / 8);
	for (i = 0; i < length; i++)
		buf[i] = 0;

	spin_lock_irqsave(&v->lock, flags);

	for (i = 0; i < VUSB_PORTS; i++) {
		struct vusb_device *dev = &v->device[i];

		/* Check status for each port */
		dprintk(D_PORT2, "check port %u (%08x)\n", v->device[i].port,
				v->device[i].port_status);
		if ((dev->port_status & PORT_C_MASK) != 0) {
			if (i < 7)
				buf[0] |= 1 << (i + 1);
			else if (i < 15)
				buf[1] |= 1 << (i - 7);
			else if (i < 23)
				buf[2] |= 1 << (i - 15);
			else
				buf[3] |= 1 << (i - 23);
			dprintk(D_PORT2, "port %u status 0x%08x has changed\n",
				    dev->port, dev->port_status);
			changed = 1;
		}

                if (dev->port_status & USB_PORT_STAT_CONNECTION)
                        resume = 1;
	}

	if (resume && v->rh_state == VUSB_RH_SUSPENDED)
		usb_hcd_resume_root_hub (hcd);

	ret = (changed) ? length : 0;

	spin_unlock_irqrestore(&v->lock, flags);
	dprintk(D_MISC, "<vusb_hub_status %d\n", ret);

	return ret;
}

/* Hub descriptor */
static void
vusb_hub_descriptor(struct usb_hub_descriptor *desc)
{
	u16 temp;

	desc->bDescriptorType = 0x29;
	desc->bPwrOn2PwrGood = 10; /* echi 1.0, 2.3.9 says 20ms max */
	desc->bHubContrCurrent = 0;
	desc->bNbrPorts = VUSB_PORTS;

	/* size of DeviceRemovable and PortPwrCtrlMask fields */
	temp = 1 + (VUSB_PORTS / 8);
	desc->bDescLength = 7 + 2 * temp;

	/* bitmaps for DeviceRemovable and PortPwrCtrlMask */

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) || (defined(RHEL_RELEASE_CODE)) )
	/* The union was introduced to support USB 3.0 */
	memset(&desc->u.hs.DeviceRemovable[0], 0, temp);
	memset(&desc->u.hs.DeviceRemovable[temp], 0xff, temp);
#else
	memset(&desc->DeviceRemovable[0], 0, temp);
	memset(&desc->DeviceRemovable[temp], 0xff, temp);
#endif

	/* per-port over current reporting and no power switching */
	temp = 0x00a;
	desc->wHubCharacteristics = cpu_to_le16(temp);
}

static int
vusb_hub_control(struct usb_hcd *hcd, u16	typeReq, u16 wValue,
				   u16	wIndex, char *buf, u16	wLength)
{
	struct vusb *v;
	int	retval = 0;
	unsigned long flags;
	u32 status;

	dprintk(D_CTRL, ">vusb_hub_control %04x %04x %04x\n",
			typeReq, wIndex, wValue);

	if (!HCD_HW_ACCESSIBLE(hcd)) {
		dprintk(D_CTRL, "<vusb_hub_control %d\n", ETIMEDOUT);
		return -ETIMEDOUT;
	}

	v = hcd_to_vusb (hcd);
	spin_lock_irqsave (&v->lock, flags);
	switch (typeReq) {
	case ClearHubFeature:
		break;
	case ClearPortFeature:
		dprintk(D_CTRL, "ClearPortFeature port %d val: 0x%04x\n",
				wIndex, wValue);
		vusb_check_port("ClearPortFeature", wIndex);
	    clear_port_feature(v, vusb_device_by_port(v, wIndex), wValue);
		break;
	case GetHubDescriptor:
		vusb_hub_descriptor ((struct usb_hub_descriptor *)buf);
		break;
	case GetHubStatus:
		/* Always local power supply good and no over-current exists. */
		*(__le32 *) buf = cpu_to_le32 (0);
		break;
	case GetPortStatus:
		vusb_check_port("GetPortStatus", wIndex);
		status = vusb_device_by_port(v, wIndex)->port_status;
		status = v->device[wIndex-1].port_status;
		dprintk(D_CTRL, "GetPortStatus port %d = 0x%08x\n", wIndex, status);
		((__le16 *) buf)[0] = cpu_to_le16 (status);
		((__le16 *) buf)[1] = cpu_to_le16 (status >> 16);
		break;
	case SetHubFeature:
		retval = -EPIPE;
		break;
	case SetPortFeature:
		vusb_check_port("SetPortStatus", wIndex);
		dprintk(D_CTRL, "SetPortFeature port %d val: 0x%04x\n", wIndex, wValue);
	    set_port_feature(v, vusb_device_by_port(v, wIndex), wValue);
		break;

	default:
		dev_dbg (vusb_dev(v),
			"hub control req%04x v%04x i%04x l%d\n",
			typeReq, wValue, wIndex, wLength);

		/* "protocol stall" on error */
		retval = -EPIPE;
	}
	spin_unlock_irqrestore (&v->lock, flags);

	if (wIndex >= 1 && wIndex <= VUSB_PORTS) {
		if ((vusb_device_by_port(v, wIndex)->port_status & PORT_C_MASK) != 0)
			 usb_hcd_poll_rh_status (hcd);
	}

	dprintk(D_MISC, "<vusb_hub_control %d\n", retval);
	return retval;
}

#ifdef CONFIG_PM
static int
vusb_bus_suspend(struct usb_hcd *hcd)
{
	struct vusb *v = hcd_to_vusb(hcd);
	unsigned long flags;

	dprintk(D_PM, "Bus suspend\n");

	spin_lock_irqsave(&v->lock, flags);
	v->rh_state = VUSB_RH_SUSPENDED;
	spin_unlock_irqrestore(&v->lock, flags);

	return 0;
}

static int
vusb_bus_resume(struct usb_hcd *hcd)
{
	struct vusb *v = hcd_to_vusb(hcd);
	int rc = 0;

	dprintk(D_PM, "Bus resume\n");

	spin_lock_irq(&v->lock);
	if (!HCD_HW_ACCESSIBLE(hcd)) {
		rc = -ESHUTDOWN;
	} else {
		v->rh_state = VUSB_RH_RUNNING;
		hcd->state = HC_STATE_RUNNING;
	}
	spin_unlock_irq (&v->lock);
	return rc;
}
#endif /* CONFIG_PM */


static const struct hc_driver vusb_hcd = {
	.description = (char *) driver_name,
	.product_desc =	DRIVER_DESC,
	.hcd_priv_size = sizeof(struct vusb),

	.flags = HCD_USB2,

//	.reset = vusb_setup,
	.start = vusb_start,
	.stop =	vusb_stop,

	.urb_enqueue = vusb_urb_enqueue,
	.urb_dequeue = vusb_urb_dequeue,

	.get_frame_number = vusb_get_frame,

	.hub_status_data = vusb_hub_status,
	.hub_control = vusb_hub_control,
#ifdef CONFIG_PM
	.bus_suspend = vusb_bus_suspend,
	.bus_resume = vusb_bus_resume,
#endif /* CONFIG_PM */
};

#define CHECK_OPS(v, opname)				\
	do {						\
		if (!(v)->fp->f_op->opname) {		\
			eprintk("missing "#opname"\n");	\
			r = -EBADF;			\
			goto err;			\
		}					\
	} while (0)

/* Create a v4v socket */
static int
vusb_open(struct vusb *v)
{
	int r;
	v4v_addr_t v4v_addr;
	mm_segment_t oldfs;

	/* Use kernel address-space to avoid -EFAULT during address checking */
	oldfs = get_fs();
	set_fs(get_ds());

	/* TODO: create a special V4V API for linux module */
	v->fp = filp_open("/dev/v4v_stream", FMODE_READ | FMODE_WRITE, 0);
	if (IS_ERR(v->fp)) {
		r = PTR_ERR(v->fp);
		eprintk("could not open /dev/v4v_stream: %d\n", r);
		return r;
	}

	/* Sanity check on file operations */
	CHECK_OPS(v, unlocked_ioctl);
	CHECK_OPS(v, write);
	CHECK_OPS(v, read);

	v4v_addr.port = VUSB_V4V_PORT;
	v4v_addr.domain = VUSB_V4V_DOMID;

	r = v->fp->f_op->unlocked_ioctl(v->fp, V4VIOCCONNECT,
			(unsigned long)&v4v_addr);
	if (r < 0) {
		eprintk("ioctl(V4VIOCCONNECT) failed: %d\n", r);
		goto err;
	}

	dprintk(D_V4V1, "connection succeeded\n");

	/* Restore the previous address-space */
	set_fs(oldfs);

	return 0;

err:
	filp_close(v->fp, NULL);

	/* Restore the previous address-space */
	set_fs(oldfs);

	return r;
}

#undef CHECK_OPS

/* Close v4v socket */
static void
vusb_close(struct vusb *v)
{
	iprintk("V4V close\n");
	filp_close(v->fp, NULL);
}

/* Write on v4v socket. FIXME not signal safe */
static int
vusb_write(struct vusb *v, const void *buf, u32 len)
{
	int r;

	dprintk(D_V4V2, "v4v_write %d\n", len);

	r = v->fp->f_op->write(v->fp, buf, len, NULL);

	dprintk(D_V4V2, "write returned %d\n", r);

	return r;
}

static int
vusb_read(struct vusb *v, void *buf, u32 len)
{
	int r;

	dprintk(D_V4V2, "v4v_read %d\n", len);

	r = v->fp->f_op->read(v->fp, buf, len, 0L);

	dprintk(D_V4V2, "read returned %d\n", r);

	return r;
}

/**
 * Inititialize a packet header to send
 * @packet: packet to initialize (already allocated)
 * @devid: device id used to discuss with the host
 * @command: what do we want?
 * @hlen: size of header
 * @dlen: size of data
 */
static void
vusb_initialize_packet(struct vusb *v, void *packet, u16 devid,
		u8 command, u32 hlen, u32 dlen)
{
	dprintk(D_URB2, "allocate packet len=%u\n",  hlen + dlen);
	/* STUB */
}

/*
 * Send a request to the host
 * A packet is describe as multiple iovec
 * TODO: Need to be implement in v4v
 */
static int
vusb_send_packet(struct vusb *v, const struct iovec *iovec, size_t niov)
{
	int r, s;
	size_t i;

	r = 0;
	s = 0;

	for (i = 0; i < niov; i++) {
		/* TODO: Add branch prediction */
		if (!iovec[i].iov_base || !iovec[i].iov_len)
			continue;
		dprint_hex_dump(D_URB2, "UC: ", DUMP_PREFIX_OFFSET, 16, 1,
				iovec[i].iov_base, iovec[i].iov_len, true);
		/* TODO: good check of return (-EINTR, no all data copied...) */
		r = vusb_write(v, iovec[i].iov_base, iovec[i].iov_len);
		if (r < 0)
			goto err_send;
		s += r;
	}

	dprintk(D_MISC, "Send return %d\n", s);

	return r;

err_send:
	dprintk(D_MISC, "Send return %d\n", r);

	return r;
}

static int
vusb_add_device(struct vusb *v, u16 id, enum usb_device_speed speed)
{
	u16 i;
	int retval = 0;
	unsigned long flags;
	struct vusb_device *dev;

	spin_lock_irqsave (&v->lock, flags);
	for (i = 0; i < VUSB_PORTS; i++) {
		if (v->device[i].present == 0)
			break;
		if (v->device[i].deviceid == id) {
			wprintk("Device id 0x%04x already exists on port %d\n",
			       id, v->device[i].port);
			retval = -EEXIST;
			goto out;
		}
	}

	if (i >= VUSB_PORTS) {
		printk(KERN_INFO "Attempt to add a device but no free ports on the root hub.\n");
		retval = -ENOMEM;
		goto out;
	}
	dev = &v->device[i];

	dev->present = 1;
	dev->deviceid = id;
	dev->speed = speed;
	dev->port_status |= usb_speed_to_port_stat(speed)
					 | USB_PORT_STAT_CONNECTION
					 | USB_PORT_STAT_C_CONNECTION << 16;

	dprintk(D_PORT1, "new status: 0x%08x speed: 0x%04x\n",
			dev->port_status, speed);
	set_link_state(v, dev);
out:
	spin_unlock_irqrestore (&v->lock, flags);
	usb_hcd_poll_rh_status (vusb_to_hcd (v));
	return 0;
}

/*
 * Convenient alias to declare an iovec
 * @packet: name of the packet
 * @nchunk: number of chunk (ex: 2 => header + data)
 */
#define vusb_create_packet(name, nchunk) struct iovec name[(nchunk)]


/* Convenient alias to set header/data */
#define vusb_iov_set(packet, off, data, len)			\
	do {							\
		(packet)[(off)].iov_base = (data);		\
		(packet)[(off)].iov_len = (len);		\
	} while (0)

#define vusb_set_packet_header(packet, header, hlen)		\
	vusb_iov_set(packet, 0, header, hlen)

#define vusb_set_packet_data(packet, data, dlen)		\
	vusb_iov_set(packet, 1, data, dlen)

/*
 * Send a bind request
 * Ask the host to open a connection
 * return 0 if the packet was sent
 */
static int
vusb_send_bind_request(struct vusb *v)
{
	vusb_create_packet(iovec, 1);
	int r;

	/* STUB setup bind packet */

	r = vusb_send_packet(v, iovec, 1);

	if (r >= 0) { /* Wait the host answer */
		v->state = VUSB_WAIT_BIND_RESPONSE;
		r = 0;
	}

	return r;
}

/*
 * Send a bind commit
 * Like TCP notify the host we received the ACK
 */
static int
vusb_send_bind_commit(struct vusb *v)
{
	vusb_create_packet(iovec, 1);
	int r;

	/* STUB setup bind commit packet to ACK */

	r = vusb_send_packet(v, iovec, 1);

	if (r >= 0) { /* The thread can now run */
		v->state = VUSB_RUNNING;
		r = 0;
	}

	return r;
}

/**
 * A new device is attached to the guest
 * TODO: Reject device
 */
static int
vusb_handle_announce_device(struct vusb *v, const void *packet)
{
	vusb_create_packet(iovec, 1);
	int r;
	enum usb_device_speed speed = 0;

	/* STUB got announcement of new device */

	/* STUB set speed... 
	speed = USB_SPEED_LOW;
	speed = USB_SPEED_FULL;
	speed = USB_SPEED_HIGH;
	*/

	r = vusb_add_device(v, 0 /* STUB logical device ID */, speed);

	if (r) /* TODO: Handle reject device here */
		return r;

	/* STUB setup packet and accept the device */

	return vusb_send_packet(v, iovec, 1);
}

/*
 * A device has gone
 * TODO: remove all URB related to this device
 */
static void
vusb_handle_device_gone(struct vusb *v, const void *packet)
{
	struct vusb_device *device = NULL;
	unsigned long flags;

	spin_lock_irqsave(&v->lock, flags);

	device = vusb_device_by_devid(v, 0 /* STUB logical device ID */);
	if (device) {
		dprintk(D_PORT1, "Remove device from port %u\n", device->port);
		device->present = 0;
		set_link_state(v, device);
		/* Update hub status */
		v->poll = 1;
	} else
		wprintk("Device gone message for unregister device?!\n");

	spin_unlock_irqrestore(&v->lock, flags);
}

/* Retrieve a URB by handle */
static struct urbp*
vusb_urb_by_handle(struct vusb *v, struct vusb_device *dev, u16 handle)
{
	struct urbp *urbp;

	list_for_each_entry(urbp, &v->urbp_list, urbp_list) {
		/*
		 * Check both handle and port to avoid to use an URB
		 * of another device
		 */
		if (urbp->handle == handle && urbp->port == dev->port)
			return urbp;
	}

	dprintk(D_URB1, "Unable to retrieve URB handle 0x%x port %u\n",
		handle, dev->port);
	vusb_urbp_list_dump(v, __FUNCTION__);

	return NULL;
}

/* Common part to finish an URB request */
static void
vusb_urb_common_finish(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp, bool in, u32 len, const u8 *data)
{
	struct urb *urb = urbp->urb;

	if (!in) { /* Outbound */
		dprintk(D_URB2, "Outgoing URB completed status %d\n",
			urb->status);
		/* Sanity check on len, should be 0 */
		if (len) {
			wprintk("Data not expected for outgoing URB\n");
			urb->status = -EIO;
		} else {
			/*
			 * FIXME: move this part in send
			 * For outgoing URB, the actual length is the length
			 * transfered to the vusb daemon
			 */
			urb->actual_length = urb->transfer_buffer_length;
		}
	} else { /* Inbound */
		dprintk(D_URB2, "Incoming URB completed status %d len %u\n",
			urb->status, len);
		/*
		 * Sanity check on len, should be less or equal to
		 * the length of the transfer buffer
		 */
		if (len > urb->transfer_buffer_length) {
			wprintk("Length mismatch for incoming URB"
				" (wanted %u bug got %u)\n",
				urb->transfer_buffer_length, len);
			urb->status = -EIO;
		} else {
			dprintk(D_URB2, "In %u bytes out of %u\n",
				len, urb->transfer_buffer_length);

			urb->actual_length = len;
			/* FIXME: use transfer buffer directly to read */
			if (len > 0)
				memcpy(urb->transfer_buffer, data, len);
		}
	}

	vusb_urbp_release(v, dev, urbp);
}

/*
 * Finish an isochronous URB
 */
static void
vusb_urb_isochronous_finish(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp, u32 len, const u8 *data)
{
	struct urb *urb = urbp->urb;
	u32 hlen = 0 /* STUB get header lenght */;
	u32 dlen = 0;
	int i;

	/* STUB sanity check ISO URB */

	/* STUB if data is not the response, move ptr */

	for (i = 0; i < urb->number_of_packets; i++) {
		struct usb_iso_packet_descriptor *desc = &urb->iso_frame_desc[i];
		u32 plen = 0 /* STUB ISO response lenght */;

		/* Sanity check on packet length */
		if (plen > desc->length) {
			wprintk("iso packet %d too much data\n", i);
			goto iso_err;
		}

		desc->actual_length = plen;
		desc->status = 0 /* STUB ISO status */;

		if (usb_urb_dir_in(urb)) {
			/* Do sanity check each time on effective data length */
			if (len < (hlen + dlen + plen)) {
				wprintk("Short URB Iso Response Data."
					"Expected %u got %u\n",
					dlen + plen, len - hlen);
				goto iso_err;
			}
			/* Copy to the right offset */
			memcpy(&(((u8 *)urb->transfer_buffer)[desc->offset]),
				&data[dlen], plen);
		}
		dlen += plen;
	}

	urb->actual_length = dlen;

	vusb_urbp_release(v, dev, urbp);
	return;

iso_err:
	urb->status = -EIO;
	for (i = 0; i < urb->number_of_packets; i++) {
		urb->iso_frame_desc[i].actual_length = 0;
		urb->iso_frame_desc[i].status = urb->status;
	}
	urb->actual_length = 0;

	vusb_urbp_release(v, dev, urbp);
}

/* Finish a control URB */
static void
vusb_urb_control_finish(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp, u32 len, const u8 *data)
{
	const struct usb_ctrlrequest *ctrl;
	bool in;

	ctrl = (struct usb_ctrlrequest *)urbp->urb->setup_packet;

	in = (ctrl->bRequestType & USB_DIR_IN) != 0;

	vusb_urb_common_finish(v, dev, urbp, in, len, data);
}

/* Finish a bulk URB */
static void
vusb_urb_bulk_finish(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp, u32 len, const u8 *data)
{
	vusb_urb_common_finish(v, dev, urbp,
			usb_urb_dir_in(urbp->urb),
			len, data);
}

/* Finish an interrupt URB */
static void
vusb_urb_interrupt_finish(struct vusb *v, struct vusb_device *dev,
		struct urbp *urbp, u32 len, const u8 *data)
{
	vusb_urb_common_finish(v, dev, urbp,
			usb_urb_dir_in(urbp->urb),
			len, data);
}

/* Convert status to errno */
static int
vusb_status_to_errno(u32 status)
{
	int32_t st = status;

	switch (status) {
	case VUSB_URB_STATUS_SUCCESS:
		return 0;
	/* STUB probably want others */
	case VUSB_URB_STATUS_FAILURE:
		return -EIO;
	default:
		if (st < 0) /* Already an errno */
			return st;
		else
			return -EIO;
	}
}

#ifdef VUSB_DEBUG
/* Convert status to a string */
static const char*
vusb_status_to_string(u32 status)
{
	int32_t st = status;

	switch (status) {
	case VUSB_URB_STATUS_SUCCESS:
		return "SUCCESS";
	/* STUB probably want others */
	case VUSB_URB_STATUS_FAILURE:
		return "FAILURE";
	default:
		if (st < 0) /* Already an errno */
			return "ERRNO";
		else
			return "UNKNOWN";
	}
}
#endif /* VUSB_DEBUG */

/*
 * Finish an URB request
 * @packet: used by isochronous URB because we need the header FIXME
 */
static void
vusb_urb_finish(struct vusb *v, struct vusb_device *dev, u16 handle,
		u32 status, u32 len, const u8 *data)
{
	struct urbp *urbp;
	struct urb *urb;

	urbp = vusb_urb_by_handle(v, dev, handle);

	if (!urbp) {
		dprintk(D_WARN, "Bad handle (0x%x) for Device ID (%u)\n",
			handle, dev->deviceid);
		return;
	}

	urb = urbp->urb;
	urb->status = vusb_status_to_errno(status);


	switch (usb_pipetype(urb->pipe)) {
	case PIPE_ISOCHRONOUS:
		vusb_urb_isochronous_finish(v, dev, urbp, len, data);
		break;

	case PIPE_CONTROL:
		vusb_urb_control_finish(v, dev, urbp, len, data);
		break;

	case PIPE_INTERRUPT:
		vusb_urb_interrupt_finish(v, dev, urbp, len, data);
		break;

	case PIPE_BULK:
		vusb_urb_bulk_finish(v, dev, urbp, len, data);
		break;

	default:
		wprintk("Unknow pipe type %u\n",
			usb_pipetype(urb->pipe));
	}
}

/* Handle command URB response */
static void
vusb_handle_urb_response(struct vusb *v, const void *packet)
{
	unsigned long flags;
	struct vusb_device *dev;
	u16 handle = 0 /* STUB logical handle */;
	u32 status = 0;
	u32 len = 0;

	/* STUB sanity check and get response values */

	spin_lock_irqsave (&v->lock, flags);

	dev = vusb_device_by_devid(v, 0 /* STUB logical device ID */);
	if (!dev) {
		wprintk("Bad device ID (%u) in URB response\n", 0);
		goto out;
	}

	vusb_urb_finish(v, dev, handle, status, len, NULL /* STUB the response data */);
out:
	spin_unlock_irqrestore(&v->lock, flags);
}

/* Handle command URB status */
static void
vusb_handle_urb_status(struct vusb *v, const void *packet)
{
	unsigned long flags;
	struct vusb_device *dev;
	u16 handle = 0 /* STUB logical handle */;
	u32 status = 0;

	/* STUB sanity check and get status values */

	spin_lock_irqsave (&v->lock, flags);

	dev = vusb_device_by_devid(v, 0 /* STUB logical device ID */);
	if (!dev) {
		wprintk("Bad device ID (%u) in URB Status\n", 0);
		goto out;
	}

	vusb_urb_finish(v, dev, handle, status, 0, NULL);
out:
	spin_unlock_irqrestore(&v->lock, flags);
}


/* Process packet received from vusb daemon */
static int
vusb_process_packet(struct vusb *v, const void *packet)
{
	int res = 0;

	switch (v->state) {
	case VUSB_WAIT_BIND_RESPONSE:
		iprintk("Wait bind response send it\n");

		res = vusb_send_bind_commit(v);
		if (res != 0) {
			eprintk("Failed to send bind commit command\n");
			return res;
		}
		break;

	case VUSB_RUNNING:
		/* STUB handle events calling one of: */
		vusb_handle_announce_device(v, packet);
		vusb_handle_device_gone(v, packet);
		vusb_handle_urb_response(v, packet);
		vusb_handle_urb_status(v, packet);
		break;

	default:
		wprintk("Invalid state %u in process_packet\n",	v->state);
		return -1;
	}

	return 0;
}

/*
 * Initialize an URB packet
 * @packet: packet to initialize (already allocated)
 * @command: what do we want?
 * @hlen: size of header
 * @has_data: if true, length will be the one of the transfer buffer
 */
static void
vusb_initialize_urb_packet(struct vusb *v, void *packet,
		const struct urbp *urbp, struct vusb_device *device,
		u8 command, u32 hlen, bool has_data)
{
	if (has_data) /* Outbound request */
		vusb_initialize_packet(v, packet, device->deviceid,
				command, hlen, urbp->urb->transfer_buffer_length);
	else
		vusb_initialize_packet(v, packet, device->deviceid,
				command, hlen, 0);

	/* STUB get logical handle: urbp->handle */
}

/*
 * Send an URB packet to the host
 * This function will setup the iov and add data if needed with the transfer
 * buffer
 * Doesn't fit for isochronous request
 */
static int
vusb_send_urb_packet(struct vusb *v,
		struct urbp *urbp, struct vusb_device *device,
		void *packet, u32 hlen, bool has_data)
{
	vusb_create_packet(iovec, 2);
	int r;

	vusb_set_packet_header(iovec, packet, hlen);
	if (has_data)
		vusb_set_packet_data(iovec, urbp->urb->transfer_buffer,
				urbp->urb->transfer_buffer_length);

	r = vusb_send_packet(v, iovec, (has_data) ? 2 : 1);

	if (r < 0) {
		/* An error occured drop the URB and notify the USB stack */
		urbp->state = VUSB_URBP_DROP;
		urbp->urb->status = r;
	} else
		urbp->state = VUSB_URBP_SENT;

	return r;
}

/* Convert URB transfer flags to VUSB flags */
static inline u16
vusb_urb_to_flags(struct urb *urb)
{
	u16 flags = 0;

	if (usb_urb_dir_in(urb))
		flags |= VUSB_URB_DIRECTION_IN;

	if (!(urb->transfer_flags & URB_SHORT_NOT_OK))
		flags |= VUSB_URB_SHORT_OK;

	if (urb->transfer_flags & URB_ISO_ASAP)
		flags |= VUSB_URB_ISO_TRANSFER_ASAP;

	return flags;
}

/* Retrieve endpoint from URB */
static inline u8
vusb_urb_to_endpoint(struct urb *urb)
{
	u8 endpoint = 0;

	endpoint = usb_pipeendpoint(urb->pipe);
	if (usb_urb_dir_in(urb))
		endpoint |= 0x80;

	return endpoint;
}

/* Not defined by hcd.h */
#define InterfaceOutRequest 						\
	((USB_DIR_OUT|USB_TYPE_STANDARD|USB_RECIP_INTERFACE) << 8)

/* Send an urb control to the host */
static void
vusb_send_control_urb(struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct vusb_device *d;
	void *packet;
	u32 hlen;
	const struct usb_ctrlrequest *ctrl;
	u8 bRequestType, bRequest;
	u16 typeReq, wValue, wIndex, wLength;
	bool in;
	bool has_data = 0;

	/* Convenient aliases on setup packet*/
	ctrl = (struct usb_ctrlrequest *)urb->setup_packet;
	bRequestType = ctrl->bRequestType;
	bRequest = ctrl->bRequest;
	wValue = le16_to_cpu(ctrl->wValue);
	wIndex = le16_to_cpu(ctrl->wIndex);
	wLength = le16_to_cpu(ctrl->wLength);

	typeReq = (bRequestType << 8) | bRequest;
	in = (bRequestType & USB_DIR_IN) != 0;

	dprintk(D_URB2,
		"Send Control URB Device: %u Endpoint: %u In: %u Cmd: 0x%x 0x%02x\n",
		usb_pipedevice(urb->pipe),
		usb_pipeendpoint(urb->pipe),
		in, ctrl->bRequest, ctrl->bRequestType);

	dprintk(D_URB2, "Setup packet, tb_len=%d\n", urb->transfer_buffer_length);
	dprint_hex_dump(D_URB2, "SET: ", DUMP_PREFIX_OFFSET, 16, 1, ctrl, 8, true);

	/* Retrieve the device */
	d = vusb_device_by_port(v, urbp->port);

	switch (typeReq) {
	case DeviceOutRequest | USB_REQ_SET_ADDRESS:
		/* Don't forward set address command, directly return */
		d->address = wValue;
		dprintk(D_URB2, "SET ADDRESS %u\n", d->address);
		urb->status = 0;
		urbp->state = VUSB_URBP_DONE;
		return;

	case DeviceOutRequest | USB_REQ_SET_CONFIGURATION:
		hlen = 0 /* STUB set configuration length */;
		vusb_initialize_urb_packet(v, &packet, urbp, d,
				0 /* STUB set configuration internal command */,
				hlen, false);

		/* STUB finish packet setup */
		break;

	case InterfaceOutRequest | USB_REQ_SET_INTERFACE:
		hlen = 0 /* STUB select interface length */;
		vusb_initialize_urb_packet(v, &packet, urbp, d,
				0 /* STUB select interface  internal command */,
				hlen, false);

		/* STUB finish packet setup */
		break;

	default:
		hlen = 0 /* STUB control length */;
		vusb_initialize_urb_packet(v, &packet, urbp, d,
				0 /* STUB control internal command */,
				hlen, !in);

		/* STUB finish packet setup */
	}

	vusb_send_urb_packet(v, urbp, d, &packet, hlen, has_data /* STUB may or may not have data in packet */);
}

/* Send an URB interrup command */
static void
vusb_send_interrupt_urb(struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct vusb_device *d;
	void *packet;

	dprintk(D_URB2, "Send Interrupt URB Device: %u Endpoint: %u in: %u\n",
		usb_pipedevice(urb->pipe),
		usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));

	d = vusb_device_by_port(v, urbp->port);

	vusb_initialize_urb_packet(v, &packet, urbp, d,
			0 /* STUB interrupt internal command */,
			0 /* STUB interrupt length */,
			usb_urb_dir_out(urb));

	/* STUB finish packet setup */

	vusb_send_urb_packet(v, urbp, d, &packet,
			0 /* STUB interrupt length */,
			usb_urb_dir_out(urb));
}

/* Send an URB bulk command */
static void
vusb_send_bulk_urb(struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct vusb_device *d;
	void *packet;

	dprintk(D_URB2, "Send Bulk URB Device: %u Endpoint: %u in: %u\n",
		usb_pipedevice(urb->pipe),
		usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));

	d = vusb_device_by_port(v, urbp->port);

	vusb_initialize_urb_packet(v, &packet, urbp, d,
			0 /* STUB bulk internal command */,
			0 /* STUB bulk length */,
			usb_urb_dir_out(urb));

	/* STUB finish packet setup */

	vusb_send_urb_packet(v, urbp, d, &packet,
			0 /* STUB bulk length */,
			usb_urb_dir_out(urb));
}

/* Send an isochronous urb command */
static void
vusb_send_isochronous_urb(struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct vusb_device *d;
	void *packet;
	vusb_create_packet(iovec, 3);
	/* TODO: use typeof? */
	u32 length[urb->number_of_packets]; /* avoid kmalloc */
	int i = 0;
	int r;

	dprintk(D_URB2, "Send Isochronous URB Device: %u Endpoint: %u in: %u\n",
		usb_pipedevice(urb->pipe),
		usb_pipeendpoint(urb->pipe),
		usb_urb_dir_in(urb));

	dprintk(D_URB2, "Number of packets = %u\n", urb->number_of_packets);

	d = vusb_device_by_port(v, urbp->port);

	/* Use the common urb initialization packet but fix ByteCount */
	vusb_initialize_urb_packet(v, &packet, urbp, d,
			0 /* STUB isoch internal command */,
			0 /* STUB isoch length */,
			usb_urb_dir_out(urb));

	/* STUB finish packet setup */

	for (i = 0; i < urb->number_of_packets; i++)
	{
		dprintk(D_URB2, "packet %d offset = 0x%u length = 0x%u\n",
			i, urb->iso_frame_desc[i].offset,
			urb->iso_frame_desc[i].length);
		length[i] = urb->iso_frame_desc[i].length;
	}

	vusb_iov_set(iovec, 0, &packet, 0 /* STUB isoch length */);
	vusb_iov_set(iovec, 1, length, 0 /* STUB isoch packet length */
			* urb->number_of_packets);
	if (usb_urb_dir_out(urb))
		vusb_iov_set(iovec, 2, urb->transfer_buffer,
				urb->transfer_buffer_length);

	r = vusb_send_packet(v, iovec, (usb_urb_dir_out(urb)) ? 3 : 2);

	if (r < 0) {
		/* An error occured drop the URB and notify the USB stack */
		urbp->state = VUSB_URBP_DROP;
		urbp->urb->status = r;
	} else
		urbp->state = VUSB_URBP_SENT;
}

/* Send a cancel URB command */
static void
vusb_send_cancel_urb(struct vusb *v, struct vusb_device *device,
		struct urbp *urbp)
{
	vusb_create_packet(iovec, 1);
	void *packet;

	vusb_initialize_packet(v, &packet, device->deviceid,
			0 /* STUB cancel internal command */,
			0 /* STUB cancel length */,
			0);

	/* STUB finish packet setup */

	dprintk(D_URB1, "send packet URB_CANCEL device %u port %u handle 0x%04x\n",
		device->deviceid, device->port, urbp->handle);

	vusb_set_packet_header(iovec, &packet, 0 /* STUB cancel length */);
	vusb_send_packet(v, iovec, 1);
}

/*
 * Send a reset command
 * TODO: Add return value and check return
 */
static void
vusb_send_reset_device_cmd(struct vusb *v, struct vusb_device *device)
{
	vusb_create_packet(iovec, 1);
	void *packet;

	if (!device->present) {
		wprintk("Ignore reset for not present device port %u\n", device->port);
		device->reset = 0;
		set_link_state(v, device);
		return;
	}

	dprintk(D_URB2, "Send reset command, port = %u\n", device->port);

	vusb_initialize_packet(v, &packet, device->deviceid,
			0 /* STUB reset internal command */,
			0 /* STUB reset length */,
			0);

	vusb_set_packet_header(iovec, &packet, 0 /* STUB reset length */);
	vusb_send_packet(v, iovec, 1);

	/* Signal reset completion */
	device->port_status |= (USB_PORT_STAT_C_RESET << 16);

	set_link_state(v, device);
	v->poll = 1;
}

/* Send an URB */
static void
vusb_send_urb(struct vusb *v, struct urbp *urbp)
{
	struct urb *urb = urbp->urb;
	struct vusb_device *device;
	unsigned int type;

	type = usb_pipetype(urb->pipe);

	dprintk(D_URB2, "urb handle: 0x%x status: %s pipe: %s(%u)\n",
		urbp->handle, vusb_state_to_string(urbp),
		vusb_pipe_to_string(urb), type);

	device = vusb_device_by_port(v, urbp->port);

	if (urbp->state == VUSB_URBP_NEW) {
		switch (type) {
		case PIPE_ISOCHRONOUS:
			vusb_send_isochronous_urb(v, urbp);
			break;

		case PIPE_INTERRUPT:
			vusb_send_interrupt_urb(v, urbp);
			break;

		case PIPE_CONTROL:
			vusb_send_control_urb(v, urbp);
			break;

		case PIPE_BULK:
			vusb_send_bulk_urb(v, urbp);
			break;

		default:
			wprintk("Unknown urb type %x\n", type);
		}
	} else if (urbp->state == VUSB_URBP_CANCEL) {
		vusb_send_cancel_urb(v, device, urbp);
	}

	if (urbp->state == VUSB_URBP_DONE ||
	    urbp->state == VUSB_URBP_DROP ||
	    urbp->state == VUSB_URBP_CANCEL) {
		/* Remove URB */
		dprintk(D_URB1, "URB immediate %s\n",
			vusb_state_to_string(urbp));
		vusb_urbp_release(v, device, urbp);
	}
}

/*
 * Process URB task
 * - Check if we need to reset a device
 * - Browse and send URB
 */
static void
vusb_process_urbs(struct vusb *v)
{
	struct urbp *urbp;
	struct urbp *next;
	unsigned long flags;
	u16 i;

	dprintk(D_MISC, "process_urbs()\n");

	spin_lock_irqsave(&v->lock, flags);

	/* Check if we need to reset a device */
	for (i = 0; i < VUSB_PORTS; i++) {
		if (v->device[i].reset == 1) {
			v->device[i].reset = 2;
			vusb_send_reset_device_cmd(v, &v->device[i]);
		}
	}

	/* Browse URB list */
	list_for_each_entry_safe(urbp, next, &v->urbp_list, urbp_list) {
		vusb_send_urb(v, urbp);
	}

	spin_unlock_irqrestore(&v->lock, flags);

	if (v->poll) { /* Update Hub status */
		v->poll = 0;
		usb_hcd_poll_rh_status(vusb_to_hcd(v));
	}
}

/*
 * Main task
 * - Read command
 * - Send command if the task receive an interrupt (not efficient)
 */
static void mainloop(struct vusb *v)
{
	int nr = 0;
	int expected = 0 /* STUB packet header length */;
	int count = 0;
	int r;
	/* STUB get packet header */;

	/* FIXME: check return */
	vusb_send_bind_request(v);
	do {
		nr = vusb_read(v, pbuf + count, expected - count);

		dprintk(D_V4V1, "vusb_read: %d\n", nr);

		if (nr == -EINTR || nr == -ERESTARTSYS) { /* Sig INT occured */
			/* Check if we need to stop */
			if (kthread_should_stop())
			        return;
			flush_signals(current);
			vusb_process_urbs(v);
			dprintk(D_V4V1, "vusb: got interrupted, restarting read\n");
			continue;
		} else if (nr < 0) { /* TODO: handle EAGAIN EDISCONNECT */
			wprintk("Unexpected error on read: %d\n", nr);
			return;
		} else if (nr == 0) {
			wprintk("zero read, assuming server close connection\n");
			/* TODO: Don't close the thread. Check if we can restart the connection */
			return;
		}

		count = count + nr;

		if (count < expected) {
			dprintk(D_V4V2, "Partial read, remaining: %d\n", expected-count);
			continue;
		} else  if (expected == 0 /* STUB packet header length */) {
			expected = 0 /* STUB payload length */;
			if (expected > VUSB_MAX_PACKET_SIZE) {
				wprintk("Packet too large (%u)\n", expected);
				/* TODO: Skip the packet, don't close the connection */
				return;
			}
		}

		if (count > expected) {
			BUG();
		}
		if (count == expected) {
			dprintk(D_V4V1, "All data received calling handler\n");
			r = vusb_process_packet(v, (void *)pbuf);
			if (v->poll) { /* Update Hub status */
				v->poll = 0;
				usb_hcd_poll_rh_status(vusb_to_hcd(v));
			}

			if (r < 0) {
				return;
			}
			if (r == 2) {
				vusb_process_urbs(v);
			}
			expected = 0 /* STUB packet header length */;
			count = 0;
		}
	} while(1);

	return;
}

static int
vusb_threadfunc(void *data)
{
	mm_segment_t oldfs;
	struct vusb *v = data;

	dprintk(D_V4V1, "tf: In thread\n");

	/* Fine now, as we don't return to userspace: */
	oldfs = get_fs();
	set_fs(get_ds());

	siginitsetinv(&current->blocked, sigmask(SIGINT));
	allow_signal(SIGINT);

	/* Main loop */
	set_current_state(TASK_INTERRUPTIBLE);
	mainloop(v);

	dprintk(D_V4V1, "tf: fp closed, thread going idle\n");

	if (!kthread_should_stop())
		wprintk("Unexpected V4V close\n");

	vusb_worker_cleanup(v);

	set_fs(oldfs);
	while (!kthread_should_stop()) {
		schedule_timeout(100000);
	}
	dprintk(D_V4V1, "tf: Thread exiting\n");
	return 0;
}

/* Platform probe */
static int
vusb_hcd_probe(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	int retval;
	struct vusb *v;

	if (usb_disabled())
		return -ENODEV;

	dprintk(D_MISC, ">vusb_hcd_probe\n");
	dev_info(&pdev->dev, "%s, driver " DRIVER_VERSION "\n", driver_desc);

	hcd = usb_create_hcd(&vusb_hcd, &pdev->dev, dev_name(&pdev->dev));
	if (!hcd)
		return -ENOMEM;
	/* Indicate the USB stack that both Super and Full Speed are supported */
	hcd->has_tt = 1;

	v = hcd_to_vusb (hcd);

	spin_lock_init(&v->lock);
	INIT_LIST_HEAD(&v->vdev_list);
	INIT_LIST_HEAD(&v->urbp_list);

	retval = vusb_worker_start(v);
	if (retval != 0)
		goto err_worker;

	retval = usb_add_hcd(hcd, 0, 0);
	if (retval != 0)
		goto err_add;

	dprintk(D_MISC, "<vusb_hcd_probe %d\n", retval);

	return 0;

err_add:
	vusb_worker_stop(v);
err_worker:
	usb_put_hcd(hcd);

	dprintk(D_MISC, "<vusb_hcd_probe %d\n", retval);

	return retval;
}

/* Platform remove */
static int
vusb_hcd_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	struct vusb *v;

	hcd = platform_get_drvdata(pdev);

	/*
	 * A warning will result: "IRQ 0 already free".
	 * It seems the linux kernel doesn't set hcd->irq to -1 when IRQ
	 * is not enabled for a USB driver. So we put an hack for this
	 * before calling usb_remove_hcd().
	 */
	hcd->irq = -1;

	usb_remove_hcd(hcd);

	v = hcd_to_vusb(hcd);

	/* Stop the main thread and release its memory */
	vusb_worker_stop(v);

	usb_put_hcd (hcd);

	return 0;
}

#ifdef CONFIG_PM
/*
 * Platform freeze
 * Called during hibernation process
 */
static int
vusb_hcd_freeze(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct usb_hcd *hcd;
	struct vusb *v;
	int rc = 0;
	unsigned long flags;

	iprintk("HCD freeze\n");

	hcd = platform_get_drvdata(pdev);
	v = hcd_to_vusb(hcd);
	spin_lock_irqsave(&v->lock, flags);

	dprintk(D_PM, "root hub state %s (%u)\n",
		vusb_rhstate_to_string(v),
		v->rh_state);

	if (v->rh_state == VUSB_RH_RUNNING) {
		wprintk("Root hub isn't suspended!\n");
		rc = -EBUSY;
	} else
		clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	spin_unlock_irqrestore(&v->lock, flags);

	if (rc == 0)
		vusb_worker_stop(v);

	return rc;
}

/* Platform restore */
static int
vusb_hcd_restore(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct usb_hcd *hcd;
	unsigned long flags;
	struct vusb *v;
	int rc = 0;

	iprintk("HCD restore\n");

	hcd = platform_get_drvdata(pdev);
	v = hcd_to_vusb(hcd);

	spin_lock_irqsave(&v->lock, flags);
	set_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	spin_unlock_irqrestore(&v->lock, flags);

	rc = vusb_worker_start(v);
	if (rc != 0)
		usb_hcd_poll_rh_status (hcd);

	return rc;
}
#endif /* CONFIG_PM */

#ifdef CONFIG_PM
static const struct dev_pm_ops vusb_hcd_pm = {
	.freeze = vusb_hcd_freeze,
	.restore = vusb_hcd_restore,
	.thaw = vusb_hcd_restore,
};
#endif /* CONFIG_PM */

static struct platform_driver vusb_hcd_driver = {
	.probe = vusb_hcd_probe,
	.remove = vusb_hcd_remove,
	.driver = {
		.name = (char *) driver_name,
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &vusb_hcd_pm,
#endif /* CONFIG_PM */
	},
};


static void
vusb_cleanup (void)
{
	iprintk("clean up\n");
	if (pbuf) {
		kfree(pbuf);
	}
	platform_device_unregister(the_vusb_hcd_pdev);
	platform_driver_unregister(&vusb_hcd_driver);
}


static int __init
vusb_init (void)
{
	int r;

	iprintk("OpenXT USB host controller\n");

	if (usb_disabled ()) {
		wprintk("USB is disabled\n");
		return -ENODEV;
	}

	pbuf = kmalloc(VUSB_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!pbuf) {
		eprintk("Unable to allocate packet buffer\n");
		r = -ENOMEM;
		return -ENOMEM;
	}

	the_vusb_hcd_pdev = platform_device_alloc(driver_name, -1);
	if (!the_vusb_hcd_pdev) {
		eprintk("Unable to allocate platform device\n");
		r = -ENOMEM;
		goto err_platform_alloc;
	}

	r = platform_driver_register(&vusb_hcd_driver);
	if (r < 0) {
		eprintk("Unable to register the platform\n");
		goto err_driver_register;
	}

	r = platform_device_add(the_vusb_hcd_pdev);
	if (r < 0) {
		eprintk("Unable to add the platform\n");
		goto err_add_hcd;
	}

	return 0;

err_add_hcd:
	platform_driver_unregister(&vusb_hcd_driver);
err_driver_register:
	platform_device_put(the_vusb_hcd_pdev);
err_platform_alloc:
	kfree(pbuf);

	return r;
}

module_init (vusb_init);
module_exit (vusb_cleanup);
MODULE_LICENSE ("GPL");
