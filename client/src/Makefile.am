lib_LTLIBRARIES = libfamfs.la libfamfs_gotcha.la

libfamfsdir = $(includedir)
libfamfs_gotchadir = $(includedir)

libfamfs_HEADERS = unifycr.h
libfamfs_la_SOURCES = \
  unifycr-fixed.c \
  unifycr-fixed.h \
  unifycr-stack.c \
  unifycr-stack.h \
  unifycr-stdio.c \
  unifycr-stdio.h \
  unifycr-sysio.c \
  unifycr-sysio.h \
  unifycr.c \
  unifycr.h \
  unifycr-internal.h \
  unifycr-wrap.h \
  unifycr-path_utils.c \
  uthash.h \
  utlist.h \
  lf_client.c \
  lf_client.h \
  fam_stripe.c \
  fam_stripe.h

libfamfs_la_CPPFLAGS = \
  -I$(top_builddir)/common/src \
  -I$(top_builddir)/client \
  $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)
libfamfs_la_LDFLAGS = -version-info $(LIBUNIFYCR_LT_VERSION) $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS) -lcrypto -lrt -lpthread

libfamfs_la_LIBADD = $(top_builddir)/common/src/libfamfs_common.la

libfamfs_gotcha_HEADERS = unifycr.h
libfamfs_gotcha_la_SOURCES = \
  unifycr-fixed.c \
  unifycr-fixed.h \
  unifycr-stack.c \
  unifycr-stack.h \
  unifycr-stdio.c \
  unifycr-stdio.h \
  unifycr-sysio.c \
  unifycr-sysio.h \
  unifycr.c \
  unifycr.h \
  gotcha_map_unifycr_list.h \
  unifycr-internal.h \
  unifycr-wrap.h \
  unifycr-path_utils.c \
  uthash.h \
  utlist.h \
  lf_client.c \
  lf_client.h \
  fam_stripe.c \
  fam_stripe.h

libfamfs_gotcha_la_CPPFLAGS = \
  -DUNIFYCR_GOTCHA \
  -I$(top_builddir)/common/src \
  -I$(top_builddir)/client \
  $(GOTCHA_CFLAGS) $(LIBFABRIC_CFLAGS) $(MPI_CLDFLAGS)
libfamfs_gotcha_la_LDFLAGS = -version-info $(LIBUNIFYCR_LT_VERSION) $(GOTCHA_LDFLAGS) \
                             $(LIBFABRIC_LIBS) $(MPI_CFLAGS) -lgotcha -lcrypto -lrt -lpthread
libfamfs_gotcha_la_LIBADD = $(top_builddir)/common/src/libfamfs_common.la
