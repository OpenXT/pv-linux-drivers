#
# Copyright (c) 2013 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
ifneq ($(FROM_DKMS),y)
include Kbuild
else
KDIR := /lib/modules/${KVERSION}/build
ENOSTDINC_FLAGS := -I$(CURDIR)/include

mdkms:
	make -C $(KDIR) FROM_DKMS=n NOSTDINC_FLAGS="$(ENOSTDINC_FLAGS)" M=$(CURDIR) modules EXTRA_CFLAGS="-g -O2"
clean:
	make -C $(KDIR) FROM_DKMS=n M=$(CURDIR) clean
endif
else


KVERSION ?= $(shell uname -r)

KDIR := /lib/modules/${KVERSION}/build
export NOSTDINC_FLAGS := -I$(CURDIR)/include

all:
	make -C $(KDIR) V=1 M=$(CURDIR) modules EXTRA_CFLAGS="-g -O2"

install:
	install -d ${DESTDIR}/usr/include/xen
	install -m 0644 include/xen/v4v.h ${DESTDIR}/usr/include/xen
	
	install -d ${DESTDIR}/usr/include/linux
	install -m 0644 include/linux/v4v_dev.h ${DESTDIR}/usr/include/linux

clean:
	make -C $(KDIR) M=$(CURDIR) clean

endif
