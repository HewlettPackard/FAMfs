bin_PROGRAMS = unifycrd

AM_CPPFLAGS = -I$(top_srcdir)/meta/src \
              -I$(top_srcdir)/meta/src/uthash \
              -I$(top_srcdir)/meta/src/Mlog2 \
              -I$(top_srcdir)/common/src

AM_CFLAGS = -Wall $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)

unifycrd_SOURCES = arraylist.c \
                   arraylist.h \
                   unifycr_cmd_handler.c \
                   unifycr_cmd_handler.h \
                   unifycr_const.c \
                   unifycr_const.h \
                   unifycr_debug.c \
                   unifycr_debug.h \
                   unifycr_init.c \
                   unifycr_init.h \
                   unifycr_metadata.c \
                   unifycr_metadata.h \
                   unifycr_request_manager.c \
                   unifycr_request_manager.h \
                   unifycr_service_manager.c \
                   unifycr_service_manager.h \
                   unifycr_sock.c \
                   unifycr_sock.h \
                   unifycr_global.h \
                   unifycr_setup.h \
                   lf_client.c \
                   lf_client.h \
                   log.h

# Preprocessor options for inlined code from common/src/famfs_bbitops.h
unifycrd_CPPFLAGS = -mbmi2 -funroll-loops --param max-completely-peel-times=64 $(AM_CPPFLAGS)

unifycrd_LDFLAGS = -static $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)

unifycrd_LDADD = $(top_builddir)/userspace-rcu/src/liburcu.la \
                 $(top_builddir)/meta/src/libmdhim.la \
                 $(top_builddir)/common/src/libfamfs_common.la \
                 $(LEVELDB_LIBS)

CLEANFILES = $(bin_PROGRAMS)
