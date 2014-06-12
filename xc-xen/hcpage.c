/*
 * Copyright (c) 2014 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include "xen-dkms.h"
#include <xen/xen.h>

#include <linux/init.h>
#include <linux/module.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/compiler.h>

unsigned char *xc_xen_hcpage;
EXPORT_SYMBOL_GPL(xc_xen_hcpage);

enum xen_domain_type xc_xen_domain_type = XEN_NATIVE;
EXPORT_SYMBOL_GPL(xc_xen_domain_type);

static inline uint32_t l_xen_cpuid_base(void)
{
	uint32_t base, eax, ebx, ecx, edx;
	char signature[13];

	for (base = 0x40000000; base < 0x40010000; base += 0x100) {
		cpuid(base, &eax, &ebx, &ecx, &edx);
		*(uint32_t *)(signature + 0) = ebx;
		*(uint32_t *)(signature + 4) = ecx;
		*(uint32_t *)(signature + 8) = edx;
		signature[12] = 0;

#if 0
		if (!strcmp("XenVMMXenVMM", signature) && ((eax - base) >= 2))
			return base;
#endif
		if (!strcmp("XciVMMXciVMM", signature) && ((eax - base) >= 2))
			return base;
	}

	return 0;
}

static struct page* l_get_page(void *v)
{
	return is_vmalloc_addr(v) ? vmalloc_to_page(v) : virt_to_page(v);
}
static u64 get_phys_addr(void *v)
{
	struct page *pg = l_get_page(v);
	return ((u64) page_to_pfn(pg)) << PAGE_SHIFT;
}

int create_hcpage(void)
{
	uint32_t eax, ebx, ecx, edx, pages, msr, base;
	int major, minor, err;
	u64 pfn;

	err = 0;
	if (!xc_xen_hcpage) {
		xc_xen_hcpage = (unsigned char*) __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
		if (!xc_xen_hcpage)
			return -ENOMEM;
	}

	base = l_xen_cpuid_base();
	if (!base)
		return -ENODEV;
	cpuid(base + 1, &eax, &ebx, &ecx, &edx);

	major = eax >> 16;
	minor = eax & 0xffff;
	printk(KERN_INFO "Xen version %d.%d.\n", major, minor);

	cpuid(base + 2, &pages, &msr, &ecx, &edx);


	pfn = get_phys_addr(xc_xen_hcpage);
	wrmsr_safe(msr, (u32)pfn, (u32)(pfn >> 32));
	asm("wbinvd\n");

	printk(KERN_INFO "XEN hypercall page initialised\n");
	return 0;
}

int __init xen_hcpage (void)
{
	const struct kernel_symbol *ks;

	if (!l_xen_cpuid_base())
		return -ENODEV;

	ks = find_symbol("xen_domain_type", NULL, NULL, true, false);
	if (ks && ks->value && *((enum xen_domain_type *)ks->value) == XEN_HVM_DOMAIN) {
		printk(KERN_INFO "xc-xen: xen domU support already active in the kernel\n");
		return -EBUSY;
	}

	xc_xen_domain_type = XEN_HVM_DOMAIN;

	return create_hcpage();
}

void xc_free_hcpage(void)
{
	if (xc_xen_hcpage) {
		vfree(xc_xen_hcpage);
		xc_xen_hcpage = 0;	
	}
}
void xc_restore_hcpage(void)
{
	create_hcpage();
}
