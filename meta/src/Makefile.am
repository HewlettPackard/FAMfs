AM_CPPFLAGS = -I$(top_srcdir)/meta/src/Mlog2 \
              -I$(top_srcdir)/meta/src/uthash \
              -I$(top_srcdir)/common/src \
              -I$(top_srcdir)/userspace-rcu/include \
              -I$(top_srcdir)/userspace-rcu/src
AM_CPPFLAGS += -fms-extensions -funroll-loops --param max-completely-peel-times=64

AM_CFLAGS = -DLEVELDB_SUPPORT -D_GNU_SOURCE=1 $(LEVELDB_CFLAGS) $(MPI_CFLAGS)
AM_CFLAGS += -std=gnu99 -Wall -Wextra

noinst_LTLIBRARIES = libmdhim.la

libmdhim_la_SOURCES = Mlog2/mlog2.c \
                     Mlog2/mlog2.h \
                     Mlog2/mlogfacs2.h \
                     client.c \
                     client.h \
                     local_client.c \
                     local_client.h \
                     data_store.c \
                     data_store.h \
                     partitioner.c \
                     partitioner.h \
                     messages.c \
                     messages.h \
                     range_server.c \
                     range_server.h \
                     ds_leveldb.c \
                     ds_leveldb.h \
                     mdhim_options.c \
                     mdhim_options.h \
                     mdhim_private.c \
                     mdhim_private.h \
                     indexes.c \
                     indexes.h \
                     mdhim.c \
                     mdhim.h \
                     uthash/uthash.h

LDADD = $(top_builddir)/common/src/libfamfs_common.la \
        $(top_builddir)/userspace-rcu/src/liburcu.la

libmdhim_la_LIBADD = $(LDADD) -lleveldb -lurcu-qsbr -lurcu-cds

# For tests
tests_LDADD =	$(LDADD) libmdhim.la \
		$(top_builddir)/common/src/libfamfs_meta.la \
		-lurcu-qsbr -lurcu-cds

f_map_test_LDADD = $(tests_LDADD)
mpitests_LDADD = $(tests_LDADD) -lmpi
f_map_mnode_test_LDADD = $(mpitests_LDADD)
f_map_cnode_test_LDADD = $(mpitests_LDADD)

unit_tests = f_map_test f_map_mnode_test f_map_cnode_test
unit_tests_run = f_map_test f_map_mnode_test
check_tests = f_map_test
checks: ${check_tests}
check_PROGRAMS = ${check_tests}
TESTS = ${check_tests}

EXTRA_DIST = ${check_tests}
EXTRA_PROGRAMS = ${unit_tests}

tests: ${unit_tests}
test: $(addsuffix .run,$(unit_tests_run))

# Build rule to run tests
%.run: %
	./$<
	 @echo Completed run: $<

CLEANFILES = ${EXTRA_PROGRAMS} ${EXTRA_DIST}
