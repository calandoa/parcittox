AUTOMAKE_OPTIONS = gnu

if HAVE_DITTOX
SUBDIRS = doc po data dittox src
else
SUBDIRS = doc po data src
endif

DISTCLEANFILES = *.bak *.log *~

EXTRA_DIST = m4/ChangeLog  m4/ChangeLog  \
	m4 \
	autogen.sh \
	config.rpath \
	m4/ChangeLog \
	$(desktop_DATA) \
	$(autostart_DATA) \
	intltool-merge.in \
	intltool-update.in \
	intltool-extract.in

ACLOCAL_AMFLAGS = -I m4
