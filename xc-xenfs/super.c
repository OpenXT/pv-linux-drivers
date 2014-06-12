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

/*
 *  xenfs.c - a filesystem for passing info between the a domain and
 *  the hypervisor.
 *
 * 2008-10-07  Alex Zeffertt    Replaced /proc/xen/xenbus with xenfs filesystem
 *                              and /proc/xen compatibility mount point.
 *                              Turned xenfs into a loadable module.
 */

#include "xen-dkms.h"

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/magic.h>

#include <xen/xen.h>

#include "xenfs.h"

#include <asm/xen/hypervisor.h>

MODULE_DESCRIPTION("Xen filesystem");
MODULE_LICENSE("GPL");

static ssize_t capabilities_read(struct file *file, char __user *buf,
				 size_t size, loff_t *off)
{
	char *tmp = "";


	return simple_read_from_buffer(buf, size, off, tmp, strlen(tmp));
}

static const struct file_operations capabilities_file_ops = {
	.read = capabilities_read,
	.llseek = default_llseek,
};

static int xenfs_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr xenfs_files[] = {
		[1] = {},
		{ "xenbus", &xenbus_file_ops, S_IRUSR|S_IWUSR },
		{ "capabilities", &capabilities_file_ops, S_IRUGO },
		{""},
	};
	int rc;

	rc = simple_fill_super(sb, XENFS_SUPER_MAGIC, xenfs_files);
	if (rc < 0)
		return rc;


	return rc;
}

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) )
static int xenfs_get_sb(struct file_system_type *fs_type,
			int flags, const char *dev_name,
			void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, xenfs_fill_super, mnt);
}
#else
static struct dentry *xenfs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name,
				  void *data)
{
	return mount_single(fs_type, flags, data, xenfs_fill_super);
}
#endif

static struct file_system_type xenfs_type = {
	.owner =	THIS_MODULE,
	.name =		"xenfs",
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) )
	.get_sb =	xenfs_get_sb,
#else
	.mount =	xenfs_mount,
#endif
	.kill_sb =	kill_litter_super,
};

static int __init xenfs_init(void)
{
	if (xen_domain())
		return register_filesystem(&xenfs_type);

	printk(KERN_INFO "XENFS: not registering filesystem on non-xen platform\n");
	return 0;
}

static void __exit xenfs_exit(void)
{
	if (xen_domain())
		unregister_filesystem(&xenfs_type);
}

module_init(xenfs_init);
module_exit(xenfs_exit);
