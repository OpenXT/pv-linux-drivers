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

#include "xen-dkms.h"
/*
 * Handle extern requests for shutdown, reboot and sysrq
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/stop_machine.h>
#include <linux/freezer.h>
#include <linux/syscore_ops.h>

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/hvc-console.h>
#include <xen/xen-ops.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <asm/xen/hypervisor.h>
#include <linux/suspend.h>

enum shutdown_state {
	SHUTDOWN_INVALID = -1,
	SHUTDOWN_POWEROFF = 0,
	SHUTDOWN_SUSPEND = 2,
	/* Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
	   report a crash, not be instructed to crash!
	   HALT is the same as POWEROFF, as far as we're concerned.  The tools use
	   the distinction when we return the reason code to them.  */
	 SHUTDOWN_HALT = 4,
};

/* Ignore multiple shutdown requests. */
static enum shutdown_state shutting_down = SHUTDOWN_INVALID;

struct suspend_info {
	int cancelled;
	unsigned long arg; /* extra hypercall argument */
	void (*pre)(void);
	void (*post)(int cancelled);
};


static void do_s3(void)
{
	pm_suspend(PM_SUSPEND_MEM);
}
int xc_xen_hvm_init_shared_info(void);
void xen_arch_hvm_post_suspend(int suspend_cancelled)
{
	xc_xen_hvm_init_shared_info();
//	xen_unplug_emulated_devices();
}
int xc_gnttab_resume(void);
static void xc_xen_hvm_post_suspend(int cancelled)
{
	xen_arch_hvm_post_suspend(cancelled);
	xc_gnttab_resume();
}

#ifdef CONFIG_HIBERNATE_CALLBACKS
static int xen_suspend(void *data)
{
	struct suspend_info *si = data;
	int err;

	BUG_ON(!irqs_disabled());


#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,39) ) /* get_sb_pseudo */
	err = sysdev_suspend(PMSG_FREEZE);
	if (err) {
		printk(KERN_ERR "xen_suspend: system dev suspend failed: %d\n",
			err);
		return err;
	}
#endif
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39) ) /* get_sb_pseudo */
	err = syscore_suspend();
	if (err) {
		printk(KERN_ERR "xen_suspend: system core suspend failed: %d\n",
			err);
		return err;
	}
#endif

	if (si->pre)
		si->pre();

	/*
	 * This hypercall returns 1 if suspend was cancelled
	 * or the domain was merely checkpointed, and 0 if it
	 * is resuming in a new domain.
	 */
	si->cancelled = HYPERVISOR_suspend(si->arg);

	if (si->post)
		si->post(si->cancelled);

	if (!si->cancelled) {
		xen_irq_resume();
//		xen_console_resume();
//		xen_timer_resume();
	}

	syscore_resume();

	return 0;
}

static void do_suspend(void)
{
	int err;
	struct suspend_info si;

	shutting_down = SHUTDOWN_SUSPEND;

	// FIXME, need a solution for freezing tasks from dkms here
#if 0
#ifdef CONFIG_PREEMPT
	/* If the kernel is preemptible, we need to freeze all the processes
	   to prevent them from being in the middle of a pagetable update
	   during suspend. */
	err = freeze_processes();
	if (err) {
		printk(KERN_ERR "xen suspend: freeze failed %d\n", err);
		goto out;
	}
#endif
#endif

	err = dpm_suspend_start(PMSG_FREEZE);
	if (err) {
		printk(KERN_ERR "xen suspend: dpm_suspend_start %d\n", err);
		goto out_thaw;
	}

	printk(KERN_DEBUG "suspending xenstore...\n");
	xs_suspend();

	err = dpm_suspend_noirq(PMSG_FREEZE);
	if (err) {
		printk(KERN_ERR "dpm_suspend_noirq failed: %d\n", err);
		goto out_resume;
	}

	si.cancelled = 1;

	si.arg = 0UL;
	si.pre = NULL;
	si.post = &xc_xen_hvm_post_suspend;

	err = stop_machine(xen_suspend, &si, cpumask_of(0));

	dpm_resume_noirq(si.cancelled ? PMSG_THAW : PMSG_RESTORE);

	if (err) {
		printk(KERN_ERR "failed to start xen_suspend: %d\n", err);
		si.cancelled = 1;
	}

out_resume:
	if (!si.cancelled) {
//		xen_arch_resume();
		xs_resume();
	} else
		xs_suspend_cancel();

	dpm_resume_end(si.cancelled ? PMSG_THAW : PMSG_RESTORE);

//	/* Make sure timer events get retriggered on all CPUs */
//	clock_was_set();

out_thaw:
#if 0
#ifdef CONFIG_PREEMPT
	thaw_processes();
out:
#endif
#endif
	shutting_down = SHUTDOWN_INVALID;
}
#endif	/* CONFIG_HIBERNATE_CALLBACKS */
struct shutdown_handler {
	const char *command;
	void (*cb)(void);
};

static void do_poweroff(void)
{
	shutting_down = SHUTDOWN_POWEROFF;
	orderly_poweroff(false);
}

static void do_reboot(void)
{
	kernel_restart(NULL);
}

static void shutdown_handler(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	char *str;
	struct xenbus_transaction xbt;
	int err;
	static struct shutdown_handler handlers[] = {
		{ "poweroff",	do_poweroff },
		{ "halt",	do_poweroff },
		{ "reboot",	do_reboot   },
		{ "s3",	do_s3   },
#ifdef CONFIG_HIBERNATE_CALLBACKS
		{ "suspend",	do_suspend  },
		{ "hibernate",	do_suspend  },
#endif
		{NULL, NULL},
	};
	static struct shutdown_handler *handler;

	if (shutting_down != SHUTDOWN_INVALID)
		return;

 again:
	err = xc_xenbus_transaction_start(&xbt);
	if (err)
		return;

	str = (char *)xc_xenbus_read(xbt, "control", "shutdown", NULL);
	/* Ignore read errors and empty reads. */
	if (XENBUS_IS_ERR_READ(str)) {
		xc_xenbus_transaction_end(xbt, 1);
		return;
	}

	for (handler = &handlers[0]; handler->command; handler++) {
		if (strcmp(str, handler->command) == 0)
			break;
	}

	/* Only acknowledge commands which we are prepared to handle. */
	if (handler->cb)
		xenbus_write(xbt, "control", "shutdown", "");

	err = xc_xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN) {
		kfree(str);
		goto again;
	}

	if (handler->cb) {
		handler->cb();
	} else {
		printk(KERN_INFO "Ignoring shutdown request: %s\n", str);
		shutting_down = SHUTDOWN_INVALID;
	}

	kfree(str);
}


static struct xenbus_watch shutdown_watch = {
	.node = "control/shutdown",
	.callback = shutdown_handler
};

static int setup_shutdown_watcher(void)
{
	int err;

	err = xc_register_xenbus_watch(&shutdown_watch);
	if (err) {
		printk(KERN_ERR "Failed to set shutdown watcher\n");
		return err;
	}


	return 0;
}

static int shutdown_event(struct notifier_block *notifier,
			  unsigned long event,
			  void *data)
{
	setup_shutdown_watcher();
	return NOTIFY_DONE;
}

int xen_setup_shutdown_event(void)
{
	static struct notifier_block xenstore_notifier = {
		.notifier_call = shutdown_event
	};

	if (!xen_domain())
		return -ENODEV;
	register_xenstore_notifier(&xenstore_notifier);

	return 0;
}

