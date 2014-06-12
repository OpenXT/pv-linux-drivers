/******************************************************************************
 * platform-pci-unplug.c
 *
 * Xen platform PCI device driver
 * Copyright (c) 2010, Citrix
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

#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>

#include <xen/platform_pci.h>
#include <linux/device.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <linux/ide.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs.h>

#define XEN_PLATFORM_ERR_MAGIC -1
#define XEN_PLATFORM_ERR_PROTOCOL -2
#define XEN_PLATFORM_ERR_BLACKLIST -3
#define QEMU_HDD_MODEL "QEMU HARDDISK"


static int always_match(struct device *dev, void *data)
{
	return 1;
}

int check_platform_magic(void)
{
	short magic;
	char protocol;

	magic = inw(XEN_IOPORT_MAGIC);
	if (magic != XEN_IOPORT_MAGIC_VAL) {
		printk(KERN_ERR "Xen Platform PCI: unrecognised magic value\n");
		return XEN_PLATFORM_ERR_MAGIC;
	}

	protocol = inb(XEN_IOPORT_PROTOVER);

	printk(KERN_DEBUG "Xen Platform PCI: I/O protocol version %d\n",
			protocol);

	switch (protocol) {
	case 1:
		outw(XEN_IOPORT_LINUX_PRODNUM, XEN_IOPORT_PRODNUM);
		outl(XEN_IOPORT_LINUX_DRVVER, XEN_IOPORT_DRVVER);
		if (inw(XEN_IOPORT_MAGIC) != XEN_IOPORT_MAGIC_VAL) {
			printk(KERN_ERR "Xen Platform: blacklisted by host\n");
			return XEN_PLATFORM_ERR_BLACKLIST;
		}
		break;
	default:
		printk(KERN_WARNING "Xen Platform PCI: unknown I/O protocol version");
		return XEN_PLATFORM_ERR_PROTOCOL;
	}

	return 0;
}

int xc_is_initramfs_time(void)
{
	struct path rootp;
	int rc;

	if ((rc = kern_path("/", LOOKUP_FOLLOW, &rootp)))
		return rc;

	rc = -ENODEV;
	if (!rootp.mnt || !rootp.mnt->mnt_sb)
		goto path_out;

	rc = 1;
	if (rootp.mnt->mnt_sb->s_bdev && rootp.mnt->mnt_sb->s_bdev->bd_disk) {
		dev_t dt = disk_devt(rootp.mnt->mnt_sb->s_bdev->bd_disk);
		if (MAJOR(dt) > 1) {
			rc = 0;
			goto path_out;
		}
	}
path_out:
	path_put(&rootp);
	return rc;
}
EXPORT_SYMBOL_GPL(xc_is_initramfs_time);

int xc_hard_unplug_qemu_disks(void)
{
	unsigned int xen_emul_unplug = 0;

	if (check_platform_magic())
		return -ENODEV;

	xen_emul_unplug |= XEN_UNPLUG_ALL_IDE_DISKS;
	outw(xen_emul_unplug, XEN_IOPORT_UNPLUG);
	return 0;
}
EXPORT_SYMBOL_GPL(xc_hard_unplug_qemu_disks);

int xc_xen_unplug_emul_disks(void)
{
	struct device *dev, *prev;
	char model[20];
	unsigned int found = 0;
	int i, rc;


	rc = xc_is_initramfs_time();
	if (rc < 0) {
		printk(KERN_WARNING "error trying to get vfsmount info for the root dir\n");
		return rc;
	}

	if (!rc) {
		printk(KERN_INFO "unplugging can only be done at initramfs time, giving up\n");
		return -EBUSY;
	}

	if (check_platform_magic())
		return -ENODEV;

	rc = 0;

	/*
	 * We have to make sure we only unplug the quemu hdd and not the cdroms.
	 * Unfortunately removing the ide pci device would remove all ata devices 
	 * so we rather do it through scsi/ide subsystem where we can make that distinction.
	 * 
	 */

#ifdef CONFIG_SCSI
	{
		extern struct bus_type scsi_bus_type;
		struct scsi_device *sdev;
		prev = NULL;
		while ((dev = bus_find_device(&scsi_bus_type, prev, NULL, always_match))) {
			if (prev)
				put_device(prev);
			prev = dev;

			if (!scsi_is_sdev_device(dev)) {
				continue;
			}
			sdev = to_scsi_device(dev);
			if (!sdev) {
				continue;
			}
			for (i = 0; i < 16; i++)
				model[i] = (sdev->model[i] >= 0x20) ? sdev->model[i] : ' ';
			model[i] = 0;
			if (strstr(model, QEMU_HDD_MODEL) == model) {
				printk(KERN_INFO "removing scsi device scsi%d (%02d:%02d:%02d)\n",
					   sdev->host->host_no, sdev->channel, sdev->id, sdev->lun);
				put_device(prev);
				scsi_remove_device(sdev);
				++found;
				prev = NULL;
				break;
			}
		}
		if (prev)
			put_device(prev);
	}
#endif

#ifdef CONFIG_IDE
	{
		extern struct bus_type ide_bus_type;
		ide_drive_t *ide;
		struct ide_driver *ide_drv;
		prev = NULL;
		while ((dev = bus_find_device(&ide_bus_type, prev, NULL, always_match))) {
			if (prev)
				put_device(prev);
			prev = dev;

			ide = to_ide_device(dev);
			if (!ide)
				continue;
			if (ide->media != ide_disk)
				continue;
			ide_drv = to_ide_driver(dev->driver);
			if (!ide_drv->remove)
				continue;

			/* FIXME we need to better check here is indeed quemu hdd */
			printk(KERN_INFO "removing ide disk %s\n", ide->name);
			put_device(prev);
			ide_drv->remove(ide);
			++found;
			prev = NULL;
			break;
		}
		if (prev)
			put_device(prev);
	}
#endif

	if (!found) {
		/* not found */
		printk(KERN_WARNING "no qemu hdd disks found\n");
		return -ENOENT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xc_xen_unplug_emul_disks);

int xc_xen_unplug_emul_netifs(void)
{
	int xen_emul_unplug = 0;

	if (check_platform_magic())
		return -ENODEV;

	xen_emul_unplug |= XEN_UNPLUG_ALL_NICS;
	outw(xen_emul_unplug, XEN_IOPORT_UNPLUG);

	return 0;
}
EXPORT_SYMBOL_GPL(xc_xen_unplug_emul_netifs);
