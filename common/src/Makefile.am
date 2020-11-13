AM_CPPFLAGS = -fms-extensions -funroll-loops --param max-completely-peel-times=64
AM_CFLAGS = -std=gnu99 -Wall -Wextra

noinst_LTLIBRARIES = libfamfs_common.la libfamfs_meta.la

include_HEADERS = err_enumerator.h

libfamfs_commondir = $(includedir)

BASE_SRCS = f_env.h f_error.h f_stats.h \
	f_zfm.h \
	f_lf_connect.h f_lf_connect.c \
	tinyexpr.h tinyexpr.c \
	ini.h ini.c \
	err_enumerator.h err_enumerator.c cm_enumerator.h cm_enumerator.c \
	f_configurator.h f_configurator.c \
	f_stats.c \
	f_ktypes.h f_bitops.h f_bitmap.h f_bitmap.c \
	f_bbitops.h f_bbitmap.h f_bbitmap.c \
	f_dict.h f_dict.c f_pool.h f_pool.c f_layout.h f_layout.c \
	f_stripe.h f_stripe.c \
	f_maps.h f_maps.c f_util.c \
	mpi_utils.h mpi_utils.c \
	f_rbq.h f_rbq.c \
	f_lfa.h f_lfa.c \
	f_wpool.h f_wpool.c \
	tree.h seg_tree.h seg_tree.c

libfamfs_common_la_SOURCES = $(BASE_SRCS)
libfamfs_common_la_CPPFLAGS =	-D_GNU_SOURCE=1 $(AM_CPPFLAGS) $(COMMON_CPPFLAGS) \
				$(LIBFABRIC_CFLAGS) $(MPI_CFLAGS) \
				-I$(top_srcdir)/userspace-rcu/include \
				-I$(top_srcdir)/userspace-rcu/src
libfamfs_common_la_CFLAGS = $(AM_CFLAGS)
libfamfs_common_la_LDFLAGS = $(LIBFABRIC_LIBS) $(MPI_CLDFLAGS)
libfamfs_common_la_LIBADD = -lm -lnuma -lrt -lpthread -luuid

libfamfs_meta_la_SOURCES = f_map.h f_map.c f_ja.h f_ja.c
libfamfs_meta_la_CPPFLAGS = -D_GNU_SOURCE=1 $(AM_CPPFLAGS) \
			-I$(top_srcdir)/userspace-rcu/include \
			-I$(top_srcdir)/userspace-rcu/src
libfamfs_meta_la_CFLAGS = $(AM_CFLAGS)
libfamfs_meta_la_LIBADD = $(top_builddir)/userspace-rcu/src/liburcu.la \
			libfamfs_common.la -lurcu-qsbr -lurcu-cds

# For tests
LDADD = libfamfs_common.la
f_map_test_CPPFLAGS =	-D_GNU_SOURCE=1 $(AM_CPPFLAGS) \
			-I$(top_srcdir)/userspace-rcu/include \
			-I$(top_srcdir)/userspace-rcu/src
f_map_test_LDADD = libfamfs_common.la libfamfs_meta.la -lurcu-qsbr -lurcu-cds

f_shmap_test_CPPFLAGS = $(f_map_test_CPPFLAGS) $(MPI_CFLAGS) $(LIBFABRIC_CFLAGS)
f_shmap_test_LDADD = $(f_map_test_LDADD) $(MPI_CLDFLAGS)

check_tests = f_bbitops_test f_map_test
unit_tests = f_bbitops_test f_bitops_test f_map_test f_shmap_test

check_PROGRAMS = ${check_tests}
TESTS = ${check_tests}

EXTRA_DIST = ${check_tests}
EXTRA_PROGRAMS = ${unit_tests}
CLEANFILES = ${EXTRA_PROGRAMS}

checks: ${check_tests}
tests: ${unit_tests}
test: $(addsuffix .run,$(unit_tests))

# Build rule to run tests
f_shmap_test.run: f_shmap_test
	mpirun ./$<
	@echo Completed run: $<

%.run: %
	./$<
	@echo Completed run: $<
