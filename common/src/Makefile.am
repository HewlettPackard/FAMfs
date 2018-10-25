noinst_LTLIBRARIES = libfamfs_common.la

BASE_SRCS = famfs_env.h famfs_error.h famfs_stats.h \
	famfs_stripe.h \
	famfs_lf_connect.h \
	famfs_lf_connect.c \
	util.c

libfamfs_common_la_SOURCES = $(BASE_SRCS)
libfamfs_common_la_CPPFLAGS = -D_GNU_SOURCE=1 $(LIBFABRIC_CFLAGS)
libfamfs_common_la_LDFLAGS = $(LIBFABRIC_LIBS)
libfamfs_common_la_LIBADD = -lm

AM_CFLAGS = -std=gnu99 -Wall -Wextra

