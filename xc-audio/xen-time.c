/******************************************************************************
 * xen-time.c
 *
 * Xen time hypercalls
 *
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

#include <linux/init.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>


#include "xen-time.h"

/* Get the current Xen time, in nanoseconds since system boot. */
#define HVMOP_get_time              10
struct xen_hvm_get_time {
    uint64_t now;      /* OUT */
};
typedef struct xen_hvm_get_time xen_hvm_get_time_t;
DEFINE_GUEST_HANDLE(xen_hvm_get_time_t);

#define VCPUOP_get_time           14 /* arg == vcpu_get_time_t */
struct vcpu_get_time {
    uint64_t now;
};
typedef struct vcpu_get_time vcpu_get_time_t;
DEFINE_GUEST_HANDLE_STRUCT(vcpu_get_time_t);

uint64_t xc_xen_get_time(void)
{
	int rc;
	struct xen_hvm_get_time t;
	t.now = 0UL;
	rc = HYPERVISOR_hvm_op(HVMOP_get_time, &t);
	return t.now;
}

uint64_t xc_xen_pv_get_time(void)
{
	int rc;
	struct vcpu_get_time t;
	t.now = 0UL;
	rc = HYPERVISOR_vcpu_op(VCPUOP_get_time, 0, &t);
	return t.now;
}
