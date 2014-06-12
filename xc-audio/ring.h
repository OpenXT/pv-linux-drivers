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

#ifndef _XC_RING_H_
#define _XC_RING_H_

#include <linux/types.h>

typedef uint32_t XC_RING_IDX;
#define XC_RING_SIZE 1024
#define MASK_XC_RING_IDX(idx) ((idx) & (XC_RING_SIZE-1))

struct ring_t {
    char req[XC_RING_SIZE]; /* requests */
    char rsp[XC_RING_SIZE]; /* replies  */
    XC_RING_IDX req_cons, req_prod;
    XC_RING_IDX rsp_cons, rsp_prod;
};

void ring_init(struct ring_t *intf);
int ring_data_to_read(struct ring_t *intf);
int ring_read(struct ring_t *intf, void *data, unsigned len);
int ring_write(struct ring_t *intf, const void *data, unsigned int len);

#endif
