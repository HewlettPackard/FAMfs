AM_CPPFLAGS = -funroll-loops --param max-completely-peel-times=64
AM_CFLAGS = -std=gnu99 -Wall -Wextra

noinst_LTLIBRARIES = libfamfs_common.la libfamfs_meta.la

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
	famfs_ktypes.h famfs_bitops.h famfs_bitmap.h famfs_bitmap.c \
	famfs_bbitops.h famfs_bbitmap.h famfs_bbitmap.c \
	f_dict.h f_dict.c f_pool.h f_layout.h \
	famfs_maps.h famfs_maps.c util.c \
        famfs_rbq.h famfs_rbq.c \
        famfs_lfa.h

libfamfs_common_la_SOURCES = $(BASE_SRCS)
libfamfs_common_la_CPPFLAGS = -D_GNU_SOURCE=1 $(AM_CPPFLAGS) $(COMMON_CPPFLAGS) $(LIBFABRIC_CFLAGS) $(MPI_CFLAGS)
libfamfs_common_la_CFLAGS = $(AM_CFLAGS)
libfamfs_common_la_LDFLAGS = $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)
libfamfs_common_la_LIBADD = -lm -lnuma -lrt -lpthread

libfamfs_meta_la_SOURCES = f_map.h f_map.c
libfamfs_meta_la_CPPFLAGS = -D_GNU_SOURCE=1 $(AM_CPPFLAGS) $(COMMON_CPPFLAGS) \
			-I$(top_srcdir)/userspace-rcu/include \
			-I$(top_srcdir)/userspace-rcu/src
libfamfs_meta_la_CFLAGS = $(AM_CFLAGS)
libfamfs_meta_la_LIBADD = $(top_builddir)/userspace-rcu/src/liburcu.la \
			libfamfs_common.la -lurcu-qsbr -lurcu-cds

# For tests
LDADD = libfamfs_common.la

check_tests = famfs_bbitops_test
unit_tests = famfs_bbitops_test famfs_bitops_test

check_PROGRAMS = ${check_tests}
TESTS = ${check_tests}

EXTRA_DIST = ${check_tests}
EXTRA_PROGRAMS = ${unit_tests}
CLEANFILES = ${EXTRA_PROGRAMS}

checks: ${check_tests}
tests: ${unit_tests}
test: $(addsuffix .run,$(unit_tests))

# Build rule to run tests
%.run: %
	./$<
	@echo Completed run: $<
