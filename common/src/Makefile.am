noinst_LTLIBRARIES = libfamfs_common.la

include_HEADERS = err_enumerator.h

libfamfs_commondir = $(includedir)

BASE_SRCS = famfs_env.h famfs_error.h famfs_stats.h \
	famfs_stripe.h \
	famfs_lf_connect.h \
	famfs_lf_connect.c \
	tinyexpr.h tinyexpr.c \
	ini.h ini.c \
	err_enumerator.h err_enumerator.c cm_enumerator.h cm_enumerator.c \
	famfs_configurator.h famfs_configurator.c \
	famfs_stats.c \
	util.c

libfamfs_common_la_SOURCES = $(BASE_SRCS)
libfamfs_common_la_CPPFLAGS = -D_GNU_SOURCE=1 $(COMMON_CPPFLAGS) $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)
libfamfs_common_la_LDFLAGS = $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)
libfamfs_common_la_LIBADD = -lm -lnuma -lrt

AM_CFLAGS = -std=gnu99 -Wall -Wextra

