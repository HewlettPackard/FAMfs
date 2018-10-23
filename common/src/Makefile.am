lib_LTLIBRARIES = libfamfs_common.la

libfamfs_commondir = $(includedir)

BASE_SRCS = famfs_env.h famfs_error.h famfs_stats.h \
	famfs_stripe.h \
	famfs_lf_connect.h \
	famfs_lf_connect.c \
	util.c

libfamfs_common_la_SOURCES = $(BASE_SRCS)
libfamfs_common_la_CPPFLAGS = -D_GNU_SOURCE=1 $(LIBFABRIC_CFLAGS)
libfamfs_common_la_LDFLAGS = -version-info $(LIBUNIFYCR_LT_VERSION) $(LIBFABRIC_LIBS)
libfamfs_common_la_LIBADD = -lm

AM_CFLAGS = -std=gnu99 -Wall -Wextra


lib_LIBRARIES = libfamfs_common.a

libfamfs_common_a_SOURCES = $(BASE_SRCS)
libfamfs_common_a_CPPFLAGSS = -D_GNU_SOURCE=1 $(LIBFABRIC_CFLAGS)
libfamfs_common_a_LDFLAGS = -static -version-info $(LIBUNIFYCR_LT_VERSION) $(LIBFABRIC_LIBS)
