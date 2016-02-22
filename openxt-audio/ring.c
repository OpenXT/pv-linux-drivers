/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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
 * Ring ops
 *
 */

#include "ring.h"
#include <linux/version.h>
#include <linux/string.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0) )
#include <asm/barrier.h>
#else
#include <asm/system.h>
#endif

static int ring_check_indexes(XC_RING_IDX cons, XC_RING_IDX prod)
{
	return ((prod - cons) <= XC_RING_SIZE);
}
static void *ring_get_output_chunk(XC_RING_IDX cons,
			      XC_RING_IDX prod,
			      char *buf, uint32_t *len)
{
	*len = XC_RING_SIZE - MASK_XC_RING_IDX(prod);
	if ((XC_RING_SIZE - (prod - cons)) < *len)
		*len = XC_RING_SIZE - (prod - cons);
	return buf + MASK_XC_RING_IDX(prod);
}

static const void *ring_get_input_chunk(XC_RING_IDX cons,
				   XC_RING_IDX prod,
				   const char *buf, uint32_t *len)
{
	*len = XC_RING_SIZE - MASK_XC_RING_IDX(cons);
	if ((prod - cons) < *len)
		*len = prod - cons;
	return buf + MASK_XC_RING_IDX(cons);
}

int ring_data_to_read(struct ring_t *intf)
{
	return (intf->rsp_cons != intf->rsp_prod);
}
int ring_write(struct ring_t *intf, const void *data, unsigned int len)
{
	XC_RING_IDX cons, prod;

	if ((intf->req_prod - intf->req_cons) == XC_RING_SIZE)
		return -1;

	while (len != 0) {
		void *dst;
		unsigned int avail;

		cons = intf->req_cons;
		prod = intf->req_prod;
		if (!ring_check_indexes(cons, prod)) {
			intf->req_cons = intf->req_prod = 0;
			return -1;
		}
		dst = ring_get_output_chunk(cons, prod, intf->req, &avail);
		if (avail < len)
			return -1; /* FIXME ! wait here ? */
		if (avail > len)
			avail = len;

		mb();

		memcpy(dst, data, avail);
		data += avail;
		len -= avail;

		wmb();
		intf->req_prod += avail;

	}

	return 0;
}

int ring_read(struct ring_t *intf, void *data, unsigned len)
{
	XC_RING_IDX cons, prod;
	int rc = len;

	while (len != 0) {
		unsigned int avail;
		const char *src;

		if (!ring_data_to_read(intf))
			return 0;

		cons = intf->rsp_cons;
		prod = intf->rsp_prod;
		if (!ring_check_indexes(cons, prod)) {
			intf->rsp_cons = intf->rsp_prod = 0;
			return -1;
		}

		src = ring_get_input_chunk(cons, prod, intf->rsp, &avail);
		if (avail == 0)
			continue;
		if (avail > len)
			avail = len;

		rmb();

		memcpy(data, src, avail);
		data += avail;
		len -= avail;

		mb();
		intf->rsp_cons += avail;

	}

	return rc;
}

void ring_init(struct ring_t *intf)
{
	intf->rsp_cons = intf->rsp_prod = 0;
	intf->req_cons = intf->req_prod = 0;
}
