#
# Copyright (C) 2016-2021 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

VERSION=0.01.06

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2
#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

export DEB_BUILD_HARDENING=1

BINDIR=/usr/bin
MANDIR=/usr/share/man/man1
BASHDIR=/usr/share/bash-completion/completions

pagein: pagein.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)

pagein.1.gz: pagein.1
	gzip -c $< > $@

dist:
	rm -rf pagein-$(VERSION)
	mkdir pagein-$(VERSION)
	cp -rp Makefile pagein.c pagein.1 COPYING snap .travis.yml \
		bash-completion pagein-$(VERSION)
	tar -zcf pagein-$(VERSION).tar.gz pagein-$(VERSION)
	rm -rf pagein-$(VERSION)

clean:
	rm -f pagein pagein.o pagein.1.gz
	rm -f pagein-$(VERSION).tar.gz

install: pagein pagein.1.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp pagein ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp pagein.1.gz ${DESTDIR}${MANDIR}
	mkdir -p ${DESTDIR}${BASHDIR}
	cp bash-completion/pagein ${DESTDIR}${BASHDIR}
