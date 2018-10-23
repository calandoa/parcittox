AM_CFLAGS = -I$(top_srcdir) -DPARCELLITELOCALEDIR=\""$(parcellitelocaledir)"\"
INCLUDES = $(GTK_CFLAGS) $(APPINDICATOR_CFLAGS)
LDADD = $(GTK_LIBS) $(APPINDICATOR_LIBS) -lX11 -lgdk-x11-2.0 -lpango-1.0 -lgobject-2.0 -lglib-2.0

bin_PROGRAMS = parcittox

DISTCLEANFILES = *.bak *.log *~ .deps/*.P

parcittox_SOURCES = main.c main.h \
                     utils.c utils.h \
                     parcellite-i18n.h\
                     daemon.c daemon.h \
                     history.c history.h \
                     keybinder.c keybinder.h \
                     preferences.c preferences.h \
                     eggaccelerators.c eggaccelerators.h \
                     attr_list.c attr_list.h

if HAVE_DITTOX
# Dittox requirements
AM_CFLAGS += -I$(top_srcdir)/dittox -DHAVE_DITTOX
LDADD += $(top_srcdir)/dittox/libdittox.a -lstdc++ -lanl -lrt
endif

if HAVE_QR
# QRencode requirements
AM_CFLAGS += -DHAVE_QR
LDADD += -lqrencode
endif
