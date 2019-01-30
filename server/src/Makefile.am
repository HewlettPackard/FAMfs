bin_PROGRAMS = unifycrd

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

unifycrd_LDFLAGS = -static $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)

unifycrd_LDADD = $(top_builddir)/meta/src/libmdhim.a \
                 $(top_builddir)/common/src/.libs/libfamfs_common.a \
                 $(LEVELDB_LIBS) \
                 -lpthread -lm -lstdc++ -lrt -lmpi -lfabric

AM_CPPFLAGS = -I$(top_srcdir)/meta/src \
              -I$(top_srcdir)/meta/src/uthash \
              -I$(top_srcdir)/meta/src/Mlog2 \
              -I$(top_srcdir)/common/src

AM_CFLAGS = -Wall $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)

CLEANFILES = $(bin_PROGRAMS)
