AM_CPPFLAGS =	-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -fms-extensions \
		-I$(top_builddir)/common/src \
		-I$(top_builddir)/client \
		-I$(top_srcdir)/userspace-rcu/include \
		-I$(top_srcdir)/userspace-rcu/src

AM_CFLAGS =	-Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable

lib_LTLIBRARIES = libfamfs.la libfamfs_gotcha.la

libfamfsdir = $(includedir)
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
  f_helper.c \
  famfs.c \
  famfs.h \
  fam_stripe.c \
  fam_stripe.h

libfamfs_la_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -funroll-loops --param max-completely-peel-times=64 \
  $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)
libfamfs_la_LDFLAGS = \
  -static -version-info $(LIBUNIFYCR_LT_VERSION) \
  $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)
libfamfs_la_LIBADD =	$(top_builddir)/common/src/libfamfs_common.la \
		$(top_builddir)/common/src/libfamfs_meta.la \
		$(top_builddir)/userspace-rcu/src/.libs/liburcu.la \
		-lurcu-qsbr -lurcu-cds -lcrypto -lrt -lpthread

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
  f_helper.c \
  famfs.c \
  famfs.h \
  fam_stripe.c \
  fam_stripe.h

libfamfs_gotcha_la_CPPFLAGS = \
  -DUNIFYCR_GOTCHA \
  $(AM_CPPFLAGS) \
  $(GOTCHA_CFLAGS) $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)
libfamfs_gotcha_la_LDFLAGS = \
  -shared -version-info $(LIBUNIFYCR_LT_VERSION) \
  $(GOTCHA_LDFLAGS) $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS) \
  -lgotcha
libfamfs_gotcha_la_LIBADD = $(top_builddir)/common/src/libfamfs_common.la \
		-lurcu-qsbr -lurcu-cds -lcrypto -lrt -lpthread
#		$(top_builddir)/common/src/libfamfs_meta.la

