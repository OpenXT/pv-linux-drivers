/******************************************************************************
 * evtchn.c
 *
 * A simplified event channel for para-drivers in unmodified linux
 *
 * Copyright (c) 2002-2005, K A Fraser
 * Copyright (c) 2005, Intel Corporation <xiaofeng.ling@intel.com>
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 */


#include "xen-dkms.h"

#define DPRINTK(fmt, args...)				\
	pr_debug("events (%s:%d) " fmt ".\n",	\
		 __func__, __LINE__, ##args)

#include <linux/linkage.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/irqnr.h>
#include <linux/pci.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/irq.h>
#include <asm/idle.h>
#include <asm/io_apic.h>
#include <asm/sync_bitops.h>
#include <asm/xen/pci.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

#include <xen/xen.h>
#include <xen/hvm.h>
#include <xen/xen-ops.h>
#include <xen/events.h>
#include <xen/interface/xen.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/hvm/params.h>

#define is_valid_evtchn(x)	((x) != 0)
#define evtchn_from_irq(x)	(irq_evtchn[irq].evtchn)



/* IRQ <-> VIRQ mapping. */
static DEFINE_PER_CPU(int [NR_VIRQS], virq_to_irq) = {[0 ... NR_VIRQS-1] = -1};

static struct {
	spinlock_t lock;
	irq_handler_t handler;
	void *dev_id;
	int evtchn;
	int is_virq:1;
	int close:1; /* close on unbind_from_irqhandler()? */
	int inuse:1;
	int in_handler:1;
} irq_evtchn[256];
static int evtchn_to_irq[NR_EVENT_CHANNELS] = {
	[0 ...  NR_EVENT_CHANNELS-1] = -1 };

static DEFINE_SPINLOCK(irq_alloc_lock);

static void do_evtchn_tsk (unsigned long unsused);
DECLARE_TASKLET(evtchn_tasklet, do_evtchn_tsk, 0);
static LIST_HEAD(lh_evttsk);
static DEFINE_SPINLOCK(lh_evttsk_lock);

struct evttsk_entry {
	struct list_head list;
	irq_handler_t handler;
	int irq;
	void *dev_id;
};

static int alloc_xen_irq(void)
{
	static int warned;
	int irq;

	spin_lock(&irq_alloc_lock);

	for (irq = 1; irq < ARRAY_SIZE(irq_evtchn); irq++) {
		if (irq_evtchn[irq].inuse) 
			continue;
		irq_evtchn[irq].inuse = 1;
		spin_unlock(&irq_alloc_lock);
		return irq;
	}

	if (!warned) {
		warned = 1;
		printk(KERN_WARNING "No available IRQ to bind to: "
		       "increase irq_evtchn[] size in evtchn.c.\n");
	}

	spin_unlock(&irq_alloc_lock);

	return -ENOSPC;
}

static void free_xen_irq(int irq)
{
	spin_lock(&irq_alloc_lock);
	irq_evtchn[irq].inuse = 0;
	spin_unlock(&irq_alloc_lock);
}

int irq_to_evtchn_port(int irq)
{
	return irq_evtchn[irq].evtchn;
}

void mask_evtchn(int port)
{
	struct shared_info *s = xc_HYPERVISOR_shared_info;
	sync_set_bit(port, &s->evtchn_mask[0]);
}

void unmask_evtchn(int port)
{
	struct evtchn_unmask op = { .port = port };
	(void)(HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &op));
}

int xc_bind_listening_port_to_irqhandler(
	unsigned int remote_domain,
	irq_handler_t handler,
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err, irq;

	irq = alloc_xen_irq();
	if (irq < 0)
		return irq;

	spin_lock_irq(&irq_evtchn[irq].lock);

	alloc_unbound.dom        = DOMID_SELF;
	alloc_unbound.remote_dom = remote_domain;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);
	if (err) {
		spin_unlock_irq(&irq_evtchn[irq].lock);
		free_xen_irq(irq);
		return err;
	}

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = alloc_unbound.port;
	irq_evtchn[irq].close   = 1;
	irq_evtchn[irq].is_virq = 0;

	evtchn_to_irq[alloc_unbound.port] = irq;

	unmask_evtchn(alloc_unbound.port);

	spin_unlock_irq(&irq_evtchn[irq].lock);

	return irq;
}
EXPORT_SYMBOL(xc_bind_listening_port_to_irqhandler);

int bind_caller_port_to_irqhandler(
	unsigned int caller_port,
	irq_handler_t handler,
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq;

	irq = alloc_xen_irq();
	if (irq < 0)
		return irq;

	spin_lock_irq(&irq_evtchn[irq].lock);

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = caller_port;
	irq_evtchn[irq].close   = 0;
	irq_evtchn[irq].is_virq   = 0;

	evtchn_to_irq[caller_port] = irq;

	unmask_evtchn(caller_port);

	spin_unlock_irq(&irq_evtchn[irq].lock);

	return irq;
}

int xc_bind_evtchn_to_irqhandler(unsigned int evtchn,
			      irq_handler_t handler,
			      unsigned long irqflags,
			      const char *devname, void *dev_id) {
	
	return bind_caller_port_to_irqhandler(evtchn, handler, irqflags, devname, dev_id);
}
EXPORT_SYMBOL_GPL(xc_bind_evtchn_to_irqhandler);


int xc_bind_virq_to_irqhandler(unsigned int virq, unsigned int cpu,
                            irq_handler_t handler,
                            unsigned long irqflags, const char *devname, void *dev_id)
{
    struct evtchn_bind_virq bind_virq;
    int evtchn, irq;

	irq = per_cpu(virq_to_irq, cpu)[virq];
	if (irq != -1)
		return irq;

	irq = alloc_xen_irq();
	if (irq < 0)
		return irq;

	spin_lock_irq(&irq_evtchn[irq].lock);

	bind_virq.virq = virq;
	bind_virq.vcpu = cpu;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq,
					&bind_virq) != 0)
		BUG();
	evtchn = bind_virq.port;
	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = evtchn;
	irq_evtchn[irq].close   = 1;
	irq_evtchn[irq].is_virq = 1;
	evtchn_to_irq[evtchn] = irq;

	unmask_evtchn(evtchn);

	spin_unlock_irq(&irq_evtchn[irq].lock);

    return irq;
}
EXPORT_SYMBOL_GPL(xc_bind_virq_to_irqhandler);

void xc_unbind_from_irqhandler(unsigned int irq, void *dev_id)
{
	int evtchn;

	spin_lock_irq(&irq_evtchn[irq].lock);

	evtchn = evtchn_from_irq(irq);

	if (is_valid_evtchn(evtchn)) {
		evtchn_to_irq[evtchn] = -1;
		mask_evtchn(evtchn);
		if (irq_evtchn[irq].close) {
			struct evtchn_close close = { .port = evtchn };
			if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close))
				BUG();
		}
	}

	irq_evtchn[irq].handler = NULL;
	irq_evtchn[irq].evtchn  = 0;

	spin_unlock_irq(&irq_evtchn[irq].lock);

	while (irq_evtchn[irq].in_handler)
		cpu_relax();

	free_xen_irq(irq);
}
EXPORT_SYMBOL(xc_unbind_from_irqhandler);

void xc_notify_remote_via_irq(int irq)
{
	int evtchn;

	evtchn = evtchn_from_irq(irq);
	if (is_valid_evtchn(evtchn))
		notify_remote_via_evtchn(evtchn);
}
EXPORT_SYMBOL(xc_notify_remote_via_irq);

static DEFINE_PER_CPU(unsigned int, last_processed_l1i) = { BITS_PER_LONG - 1 };
static DEFINE_PER_CPU(unsigned int, last_processed_l2i) = { BITS_PER_LONG - 1 };

static inline unsigned long active_evtchns(unsigned int cpu, struct shared_info *sh,
						unsigned int idx)
{
	return (sh->evtchn_pending[idx] & ~sh->evtchn_mask[idx]);
}

static void do_evtchn_tsk(unsigned long unused)
{
	struct evttsk_entry *evt;
	unsigned long flags;
again:
	spin_lock_irqsave(&lh_evttsk_lock, flags);
	if (list_empty(&lh_evttsk)) {
		spin_unlock_irqrestore(&lh_evttsk_lock, flags);
		return;
	}
	evt = (struct evttsk_entry *) lh_evttsk.next;
	list_del(&evt->list);
	spin_unlock_irqrestore(&lh_evttsk_lock, flags);
	local_irq_enable();
	evt->handler(evt->irq, evt->dev_id);
	kfree(evt);
	goto again;
}
void xc_xen_hvm_evtchn_do_upcall(void)
{
	unsigned int l1i, l2i, port;
	int irq;
	void *dev_id;
	unsigned long masked_l1, masked_l2;
	struct evttsk_entry *eve;
	/* XXX: All events are bound to vcpu0 but irq may be redirected. */
	int cpu = 0; /*smp_processor_id();*/
	irq_handler_t handler;
	struct shared_info *s = xc_HYPERVISOR_shared_info;
	struct vcpu_info *v = &s->vcpu_info[cpu];
	unsigned long l1, l2;

	v->evtchn_upcall_pending = 0;

#ifndef CONFIG_X86 /* No need for a barrier -- XCHG is a barrier on x86. */
	/* Clear master flag /before/ clearing selector flag. */
	wmb();
#endif
	l1 = xchg(&v->evtchn_pending_sel, 0);

	l1i = per_cpu(last_processed_l1i, cpu);
	l2i = per_cpu(last_processed_l2i, cpu);

	while (l1 != 0) {

		l1i = (l1i + 1) % BITS_PER_LONG;
		masked_l1 = l1 & ((~0UL) << l1i);

		if (masked_l1 == 0) { /* if we masked out all events, wrap around to the beginning */
			l1i = BITS_PER_LONG - 1;
			l2i = BITS_PER_LONG - 1;
			continue;
		}
		l1i = __ffs(masked_l1);

		do {
			l2 = active_evtchns(cpu, s, l1i);

			l2i = (l2i + 1) % BITS_PER_LONG;
			masked_l2 = l2 & ((~0UL) << l2i);

			if (masked_l2 == 0) { /* if we masked out all events, move on */
				l2i = BITS_PER_LONG - 1;
				break;
			}
			l2i = __ffs(masked_l2);

			/* process port */
			port = (l1i * BITS_PER_LONG) + l2i;
			sync_clear_bit(port, &s->evtchn_pending[0]);

			irq = evtchn_to_irq[port];
			if (irq < 0)
				continue;

			spin_lock(&irq_evtchn[irq].lock);
			handler = irq_evtchn[irq].handler;
			dev_id  = irq_evtchn[irq].dev_id;
			if (unlikely(handler == NULL)) {
				printk("Xen IRQ%d (port %d) has no handler!\n",
				       irq, port);
				spin_unlock(&irq_evtchn[irq].lock);
				continue;
			}
			irq_evtchn[irq].in_handler = 1;
			spin_unlock(&irq_evtchn[irq].lock);

			if (irq_evtchn[irq].is_virq) {
				handler(irq, irq_evtchn[irq].dev_id);
			} else {
				eve = (struct evttsk_entry *) kmalloc(sizeof(struct evttsk_entry), GFP_ATOMIC);
				if (eve) {
					eve->handler = handler;
					eve->irq = irq;
					eve->dev_id = irq_evtchn[irq].dev_id;
					spin_lock(&lh_evttsk_lock);
					list_add_tail(&eve->list, &lh_evttsk);
					spin_unlock(&lh_evttsk_lock);
					tasklet_hi_schedule(&evtchn_tasklet);
				}
			}

			spin_lock(&irq_evtchn[irq].lock);
			irq_evtchn[irq].in_handler = 0;
			spin_unlock(&irq_evtchn[irq].lock);

			/* if this is the final port processed, we'll pick up here+1 next time */
			per_cpu(last_processed_l1i, cpu) = l1i;
			per_cpu(last_processed_l2i, cpu) = l2i;

		} while (l2i != BITS_PER_LONG - 1);

		l2 = active_evtchns(cpu, s, l1i);
		if (l2 == 0) /* we handled all ports, so we can clear the selector bit */
			l1 &= ~(1UL << l1i);
	}
}
EXPORT_SYMBOL_GPL(xc_xen_hvm_evtchn_do_upcall);


void xen_irq_resume(void)
{
	int evtchn, irq;

	for (evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++) {
		mask_evtchn(evtchn);
		evtchn_to_irq[evtchn] = -1;
	}

	for (irq = 0; irq < ARRAY_SIZE(irq_evtchn); irq++)
		irq_evtchn[irq].evtchn = 0;
}

void xc_xen_irq_init(void)
{
	int irq;

	for (irq = 0; irq < ARRAY_SIZE(irq_evtchn); irq++)
		spin_lock_init(&irq_evtchn[irq].lock);

}
EXPORT_SYMBOL_GPL(xc_xen_irq_init);
