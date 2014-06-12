/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

#ifndef _XC_XEN_MODULE_H
#define _XC_XEN_MODULE_H


int xen_hcpage (void);
void xc_free_hcpage(void);
void xc_xen_irq_init(void);
int xenbus_probe_init(void);
int xenbus_probe_resume(void);
void xenbus_remove(void);
int __init xenbus_probe_frontend_init(void);
static int platform_pci_init(struct pci_dev *pdev,
				       const struct pci_device_id *ent);
static void xc_xen_resume(struct pci_dev *pdev, int newdom);
void xs_suspend(void);
void gnttab_exit(void);
void xen_irq_resume(void);
int xc_xen_hvm_init_shared_info(void);
int	gnttab_free_foreign(void);
void xc_restore_hcpage(void);
void xc_wait_for_devices(void);
int xenbus_freeze(void);
int xenbus_restore(void);
int xenbus_thaw(void);

#endif
