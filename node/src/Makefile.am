bin_PROGRAMS	= node lf_test

node_SOURCES	= queue.h w_pool.h w_pool.c \
		node.h node.c \
		ec_perf.h ec_perf.c

lf_test_SOURCES	= lf_test.h lf_test.c \
		ec_perf.h ec_perf.c

node_LDFLAGS	= -L$(top_builddir)/node/isa-l/.libs/ $(MPI_CLDFLAGS) $(LIBFABRIC_LIBS)

node_LDADD	= -lpthread -lisal \
		$(top_builddir)/common/src/libfamfs_common.la

lf_test_LDFLAGS	= $(MPI_CLDFLAGS) $(LIBFABRIC_LIBS)

lf_test_LDADD	= -lpthread -lisal $(top_builddir)/common/src/libfamfs_common.la

AM_CPPFLAGS	= -D_GNU_SOURCE=1 \
		$(MPI_CFLAGS) $(LIBFABRIC_CFLAGS) \
		-I$(top_srcdir)/common/src \
		-I$(top_srcdir)/node/isa-l/include/ -I$(top_srcdir)/node/isa-l/erasure_code/erasure_code

AM_CFLAGS	= -std=gnu99 -Wall -Wextra

CLEANFILES	= $(bin_PROGRAMS)
