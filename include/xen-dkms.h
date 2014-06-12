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

#ifdef DKMS_WITH_INSTRUM
#undef CONFIG_TRACEPOINTS
#endif

#ifndef CONFIG_XEN
#define CONFIG_XEN
#else
//#define XC_HAS_STATIC_XEN
#endif

#ifndef CONFIG_XEN_PLATFORM_PCI
#define CONFIG_XEN_PLATFORM_PCI
#endif

#ifndef CONFIG_PCI_XEN
#define CONFIG_PCI_XEN
#endif

#ifndef CONFIG_XEN_XENBUS_FRONTEND
#define CONFIG_XEN_XENBUS_FRONTEND
#endif

#ifndef CONFIG_XEN_BLKDEV_FRONTEND
#define CONFIG_XEN_BLKDEV_FRONTEND
#endif

#ifndef CONFIG_XEN_NETDEV_FRONTEND
#define CONFIG_XEN_NETDEV_FRONTEND
#endif

#ifndef CONFIG_XENFS
#define CONFIG_XENFS
#endif

#ifdef XC_HAS_STATIC_XEN
/* exported symbols redirection ... */
#define xc_xen_hcpage hypercall_page

#define xc_xen_domain_type xen_domain_type
#define xc_machine_to_phys_mapping machine_to_phys_mapping
#define xc_machine_to_phys_nr machine_to_phys_nr
#define xc_xen_features xen_features
#define xc_HYPERVISOR_shared_info HYPERVISOR_shared_info
#define xc_xen_have_vector_callback xen_have_vector_callback

#define xc_xen_set_callback_via xen_set_callback_via
#define xc_bind_listening_port_to_irqhandler bind_listening_port_to_irqhandler
#define xc_bind_evtchn_to_irqhandler bind_evtchn_to_irqhandler
#define xc_bind_virq_to_irqhandler bind_virq_to_irqhandler
#define xc_unbind_from_irqhandler unbind_from_irqhandler
#define xc_notify_remote_via_irq notify_remote_via_irq
#define xc_xen_hvm_evtchn_do_upcall xen_hvm_evtchn_do_upcall
#define xc_xen_irq_init xen_irq_init

#define xc_xen_hvm_resume_frames xen_hvm_resume_frames
#define xc_gnttab_grant_foreign_access_ref gnttab_grant_foreign_access_ref
#define xc_gnttab_grant_foreign_access gnttab_grant_foreign_access
#define xc_gnttab_query_foreign_access gnttab_query_foreign_access
#define xc_gnttab_end_foreign_access_ref gnttab_end_foreign_access_ref
#define xc_gnttab_end_foreign_access gnttab_end_foreign_access
#define xc_gnttab_end_foreign_transfer_ref gnttab_end_foreign_transfer_ref
#define xc_gnttab_free_grant_references gnttab_free_grant_references
#define xc_gnttab_alloc_grant_references gnttab_alloc_grant_references
#define xc_gnttab_claim_grant_reference gnttab_claim_grant_reference
#define xc_gnttab_release_grant_reference gnttab_release_grant_reference
#define xc_gnttab_request_free_callback gnttab_request_free_callback
#define xc_gnttab_cancel_free_callback gnttab_cancel_free_callback

#define xc_xen_store_evtchn xen_store_evtchn
#define xc_xen_store_interface xen_store_interface
#define xc_xenbus_unregister_driver xenbus_unregister_driver
#define xc_xenbus_probe xenbus_probe
#define xc_xenbus_dev_request_and_reply xenbus_dev_request_and_reply
#define xc_xenbus_read xenbus_read
#define xc_xenbus_transaction_start xenbus_transaction_start
#define xc_xenbus_transaction_end xenbus_transaction_end
#define xc_xenbus_scanf xenbus_scanf
#define xc_xenbus_printf xenbus_printf
#define xc_xenbus_gather xenbus_gather
#define xc_register_xenbus_watch register_xenbus_watch
#define xc_unregister_xenbus_watch unregister_xenbus_watch
#define xc___xenbus_register_frontend __xenbus_register_frontend
#define xc_xenbus_strstate xenbus_strstate
#define xc_xenbus_switch_state xenbus_switch_state
#define xc_xenbus_frontend_closed xenbus_frontend_closed
#define xc_xenbus_dev_error xenbus_dev_error
#define xc_xenbus_dev_fatal xenbus_dev_fatal
#define xc_xenbus_grant_ring xenbus_grant_ring
#define xc_xenbus_alloc_evtchn xenbus_alloc_evtchn

#endif

#include <linux/list.h>
struct xc_pm_callback {
	struct list_head list;
	int (*freeze)(void);
	int (*restore)(void);
};

int xc_register_erly_pm(struct xc_pm_callback *);
int xc_unregister_early_pm(struct xc_pm_callback *);

#include <linux/version.h>
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) 0
#endif
