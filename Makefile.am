SUBDIRS = common meta node server client t

CONFIG = ordered

#ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = client/famfs.pc

CLEANFILES =

checkstyle:
	scripts/checkpatch.sh
