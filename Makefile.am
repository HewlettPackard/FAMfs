SUBDIRS = userspace-rcu common meta node server client t util

CONFIG = ordered

#ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = client/famfs.pc

CLEANFILES =

checkstyle:
	scripts/checkpatch.sh
