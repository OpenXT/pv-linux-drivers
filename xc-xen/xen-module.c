/******************************************************************************
 * platform-pci.c
 *
 * Xen platform PCI device driver
 * Copyright (c) 2005, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2012, Citrix
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include "xen-dkms.h"

#include <xen/xen.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/version.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/interface.h>
#include <xen/interface/xen.h>
#include <xen/interface/version.h>
#include <xen/interface/physdev.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/memory.h>
#include <xen/features.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/compiler.h>

#include <xen/platform_pci.h>
#include <xen/grant_table.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/hvm.h>
#include <xen/xen-ops.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/vcpu.h>

#include "xc-xen-module.h"

#define DRV_NAME    "xc-xen-platform-pci"

#define XEN_PLATFORM_ERR_MAGIC -1
#define XEN_PLATFORM_ERR_PROTOCOL -2
#define XEN_PLATFORM_ERR_BLACKLIST -3

#define INVALID_MFN2 (~0UL)


MODULE_AUTHOR("ssmith@xensource.com, stefano.stabellini@eu.citrix.com and paulian.marinca@citrix.com");
MODULE_DESCRIPTION("XenClient platform pv driver");
MODULE_LICENSE("GPL");


DEFINE_PER_CPU(struct vcpu_info *, xen_vcpu);

LIST_HEAD(xc_pm_list);
static DEFINE_MUTEX(xc_pm_mutex);

u8 xc_xen_features[XENFEAT_NR_SUBMAPS * 32];
EXPORT_SYMBOL_GPL(xc_xen_features);

struct shared_info *xc_HYPERVISOR_shared_info = 0;
EXPORT_SYMBOL_GPL(xc_HYPERVISOR_shared_info);

int xc_xen_have_vector_callback = 0;
EXPORT_SYMBOL_GPL(xc_xen_have_vector_callback);

int xc_suppress_hibernate = 0;
EXPORT_SYMBOL_GPL(xc_suppress_hibernate);

static struct shared_info *shared_info_page = 0;

static unsigned long platform_mmio;
static unsigned long platform_mmio_alloc;
static unsigned long platform_mmiolen;
static uint64_t callback_via;
static struct pci_driver platform_driver;
static int upcall_disabled = 1;

unsigned long alloc_xen_mmio(unsigned long len)
{
	unsigned long addr;

	addr = platform_mmio + platform_mmio_alloc;
	platform_mmio_alloc += len;
	BUG_ON(platform_mmio_alloc > platform_mmiolen);

	return addr;
}

static u64 get_phys_addr(void *v)
{
	struct page *pg = is_vmalloc_addr(v) ? vmalloc_to_page(v) : virt_to_page(v);
	return ((u64) page_to_pfn(pg)) << PAGE_SHIFT;
}

void xen_setup_features(void)
{
	struct xen_feature_info fi;
	int i, j;

	for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) {
		fi.submap_idx = i;
		if (HYPERVISOR_xen_version(XENVER_get_features, &fi) < 0) {
				break;
		}
		for (j = 0; j < 32; j++)
				xc_xen_features[i * 32 + j] = !!(fi.submap & 1<<j);
	}
}

void xc_free_shared_info(void)
{
	struct xen_add_to_physmap xatp;
	int rc;
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = INVALID_MFN2;
	rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
}

int xc_xen_hvm_init_shared_info(void)
{
	int cpu;
	struct xen_add_to_physmap xatp;

	if (!shared_info_page) {
		shared_info_page = (struct shared_info*) __get_free_pages(GFP_KERNEL, get_order(PAGE_SIZE));
		if (!shared_info_page)
			return -ENOMEM;
	}

	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = get_phys_addr(shared_info_page) >> PAGE_SHIFT;
	if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp))
		BUG();

	xc_HYPERVISOR_shared_info = (struct shared_info *)shared_info_page;

	/* xen_vcpu is a pointer to the vcpu_info struct in the shared_info
	 * page, we use it in the event channel upcall and in some pvclock
	 * related functions. We don't need the vcpu_info placement
	 * optimizations because we don't use any pv_mmu or pv_irq op on
	 * HVM.
	 * When xen_hvm_init_shared_info is run at boot time only vcpu 0 is
	 * online but xen_hvm_init_shared_info is run at resume time too and
	 * in that case multiple vcpus might be online. */
	/* FIXME ! what if more than XEN_LEGACY_MAX_VCPUS == 32 are used here ? */
	for_each_online_cpu(cpu) {
		per_cpu(xen_vcpu, cpu) = &xc_HYPERVISOR_shared_info->vcpu_info[cpu];
	}

	return 0;
}

static uint64_t get_callback_via(struct pci_dev *pdev)
{
	u8 pin;
	int irq;

	irq = pdev->irq;
	if (irq < 16)
		return irq; /* ISA IRQ */

	pin = pdev->pin;

	/* We don't know the GSI. Specify the PCI INTx line instead. */
	return ((uint64_t)0x01 << 56) | /* PCI INTx identifier */
		((uint64_t)pci_domain_nr(pdev->bus) << 32) |
		((uint64_t)pdev->bus->number << 16) |
		((uint64_t)(pdev->devfn & 0xff) << 8) |
		((uint64_t)(pin - 1) & 3);
}

int xc_xen_set_callback_via(uint64_t via)
{
	struct xen_hvm_param a;
	a.domid = DOMID_SELF;
	a.index = HVM_PARAM_CALLBACK_IRQ;
	a.value = via;
	return HYPERVISOR_hvm_op(HVMOP_set_param, &a);
}
EXPORT_SYMBOL_GPL(xc_xen_set_callback_via);

uint64_t xc_xen_get_time(void)
{
	int rc;
	struct xen_hvm_get_time t;
	t.now = 0UL;
	rc = HYPERVISOR_hvm_op(HVMOP_get_time, &t);
	return t.now;
}
EXPORT_SYMBOL_GPL(xc_xen_get_time);

uint64_t xc_xen_pv_get_time(void)
{
	int rc;
	struct vcpu_get_time t;
	t.now = 0UL;
	rc = HYPERVISOR_vcpu_op(VCPUOP_get_time, 0, &t);
	return t.now;
}
EXPORT_SYMBOL_GPL(xc_xen_pv_get_time);

static irqreturn_t do_hvm_evtchn_intr(int irq, void *dev_id)
{
	if (upcall_disabled)
		return IRQ_HANDLED;
	xc_xen_hvm_evtchn_do_upcall();
	return IRQ_HANDLED;
}

static int xen_allocate_irq(struct pci_dev *pdev)
{
	return request_irq(pdev->irq, do_hvm_evtchn_intr,
			IRQF_DISABLED | IRQF_NOBALANCING | IRQF_TRIGGER_RISING,
			DRV_NAME, pdev);
}

int xc_register_erly_pm(struct xc_pm_callback *pm)
{
	mutex_lock(&xc_pm_mutex);
	list_add (&pm->list, &xc_pm_list);
	mutex_unlock(&xc_pm_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(xc_register_erly_pm);
int xc_unregister_early_pm(struct xc_pm_callback *pm)
{
	mutex_lock(&xc_pm_mutex);
	list_del(&pm->list);
	mutex_unlock(&xc_pm_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(xc_unregister_early_pm);

static int do_early_freeze(void)
{
	struct xc_pm_callback *pm;

	mutex_lock(&xc_pm_mutex);
	list_for_each_entry(pm, &xc_pm_list, list) {
		if (pm->freeze)
			pm->freeze();
	}
	mutex_unlock(&xc_pm_mutex);
	return 0;
}
static int do_late_restore(void)
{
	struct xc_pm_callback *pm;

	mutex_lock(&xc_pm_mutex);
	list_for_each_entry(pm, &xc_pm_list, list) {
		if (pm->restore)
			pm->restore();
	}
	mutex_unlock(&xc_pm_mutex);
	return 0;
}

static int platform_pci_freeze_noirq(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	if (unlikely(xc_suppress_hibernate))
		return -EBUSY;
	printk(KERN_INFO "xc-xen: platform_pci_freeze_noirq\n");
	xenbus_remove();
	xen_irq_resume();

	gnttab_exit();

	free_irq(pdev->irq, pdev);
	pci_release_region(pdev, 0);
	pci_release_region(pdev, 1);
	pci_disable_device(pdev);

	xc_free_shared_info();
	xc_free_hcpage();
	return 0;
}
static int platform_pci_freeze(struct device *dev)
{
	if (unlikely(xc_suppress_hibernate))
		return -EBUSY;
	printk(KERN_INFO "xc-xen: platform_pci_freeze\n");
	do_early_freeze();
	xenbus_freeze();
	xs_suspend();
	upcall_disabled = 1;
	gnttab_free_foreign();
	return 0;
}
static int platform_pci_thaw_noirq(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	printk(KERN_INFO "xc-xen: platform_pci_thaw_noirq\n");
	xc_xen_resume(pdev, 1);
	return 0;
}

static int platform_pci_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	printk(KERN_INFO "xc-xen: platform_pci_thaw\n");
	xc_xen_resume(pdev, 0);
	xenbus_thaw();
	do_late_restore();
	return 0;
}
static int platform_pci_restore_noirq(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	printk(KERN_INFO "xc-xen: platform_pci_restore_noirq\n");
	xc_xen_resume(pdev, 1);
	return 0;
}

static int platform_pci_restore(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	printk(KERN_INFO "xc-xen: platform_pci_restore\n");
	xc_xen_resume(pdev, 0);
	xenbus_restore();
	do_late_restore();
	return 0;
}

static int platform_pci_init(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int ret;
	long ioaddr;
	long mmio_addr, mmio_len;
	unsigned int max_nr_gframes;

	platform_mmio = 0L;
	platform_mmio_alloc = 0L;
	platform_mmiolen = 0L;

	ret = pci_enable_device(pdev);
	if (ret)
		return ret;

	ioaddr = pci_resource_start(pdev, 0);

	mmio_addr = pci_resource_start(pdev, 1);
	mmio_len = pci_resource_len(pdev, 1);

	if (mmio_addr == 0 || ioaddr == 0) {
		dev_err(&pdev->dev, "no resources found\n");
		ret = -ENOENT;
		goto pci_out;
	}

	ret = pci_request_region(pdev, 1, DRV_NAME);
	if (ret < 0)
		goto pci_out;

	ret = pci_request_region(pdev, 0, DRV_NAME);
	if (ret < 0)
		goto mem_out;

	platform_mmio = mmio_addr;
	platform_mmiolen = mmio_len;

	
	max_nr_gframes = gnttab_max_grant_frames();
	xc_xen_hvm_resume_frames = alloc_xen_mmio(PAGE_SIZE * max_nr_gframes);
	ret = gnttab_init();
	if (ret)
		goto out;
	if (!xc_xen_have_vector_callback) {
		ret = xen_allocate_irq(pdev); 
		if (ret) {
			dev_warn(&pdev->dev, "request_irq failed err=%d\n", ret);
			goto out;
		}

		callback_via = get_callback_via(pdev);
		ret = xc_xen_set_callback_via(callback_via);
		if (ret) {
			dev_warn(&pdev->dev, "Unable to set the evtchn callback "
					 "err=%d\n", ret);
			goto out;
		}
	}

	return 0;

out:
	pci_release_region(pdev, 0);
mem_out:
	pci_release_region(pdev, 1);
pci_out:
	pci_disable_device(pdev);
	return ret;
}

static struct pci_device_id platform_pci_tbl[]
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinitdata
#endif
= {
	{PCI_VENDOR_ID_XEN, PCI_DEVICE_ID_XEN_PLATFORM,
		PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, platform_pci_tbl);


static struct dev_pm_ops platform_driver_pm = {
  .freeze_noirq         = platform_pci_freeze_noirq,
  .freeze		        = platform_pci_freeze,
  .thaw_noirq           = platform_pci_thaw_noirq,
  .thaw			        = platform_pci_thaw,
  .restore_noirq        = platform_pci_restore_noirq,
  .restore				= platform_pci_restore
};

static struct pci_driver platform_driver = {
	.name =           DRV_NAME,
	.probe =          platform_pci_init,
	.id_table =       platform_pci_tbl,
#ifdef CONFIG_PM
	.driver = {
		.pm = &platform_driver_pm
	}
#endif
};


static void xc_xen_resume(struct pci_dev *pdev, int no_irq)
{
	if (no_irq) {
		xc_restore_hcpage();
		xen_setup_features();

		xc_xen_hvm_init_shared_info();
		xc_xen_irq_init();
		return;
	}

	platform_pci_init(pdev, NULL);
	upcall_disabled = 0;
	xenbus_probe_resume();
	xc_wait_for_devices();
}

int platform_pci_module_init(void)
{
	upcall_disabled = 0;
	xc_xen_irq_init();
	return pci_register_driver(&platform_driver);
}


static int __init
m_init (void)
{
	int r;

	r = xen_hcpage();
	if (r)
		return r;

	if (!xen_hvm_domain())
		return -ENODEV;

	xen_setup_features();
	r = xc_xen_hvm_init_shared_info();
	if (r < 0)
		return r;

	/* because we cannot yet use callback vector facility from within 
	 * the dkms module, switch off the flag for now */
	xc_xen_have_vector_callback = 0;

	r = platform_pci_module_init();
	if (r)
		return r;

	r = xenbus_probe_init();
	if (r)
		return r;
	r = xenbus_probe_frontend_init();
	if (r)
		return r;

	printk(KERN_INFO "xc-xen module initialized\n");
	return 0;
}

module_init (m_init);
