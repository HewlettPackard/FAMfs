AM_CPPFLAGS = -I$(top_srcdir)/meta/src/Mlog2 \
              -I$(top_srcdir)/meta/src/uthash \
              -I$(top_srcdir)/common/src
AM_CPPFLAGS += -mbmi2 -funroll-loops --param max-completely-peel-times=64

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
                     uthash/uthash.h \
                     f_map.h f_map.c

libmdhim_la_LIBADD = $(top_builddir)/common/src/libfamfs_common.la -lurcu-qsbr -lurcu-cds

# unittests
LDADD = $(top_builddir)/common/src/libfamfs_common.la libmdhim.la
f_map_test_LDADD = $(LDADD) -lleveldb
unit_tests = f_map_test
EXTRA_PROGRAMS = ${unit_tests}

tests: ${unit_tests}
test: $(addsuffix .run,$(unit_tests))

# Build rule to run tests
%.run: %
	./$<
	 @echo Completed run: $<

CLEANFILES = ${EXTRA_PROGRAMS}
