libexec_PROGRAMS = test_write_gotcha test_read_gotcha test_write_static test_read_static
libexec_PROGRAMS += test_prw_gotcha test_prw_static fabtest

AM_CFLAGS = -Wall

test_gotcha_ldadd = ../src/libfamfs_gotcha.la -lmpi
test_static_ldadd = ../src/libfamfs.la -lmpi
test_static_ldflags = -static $(CP_WRAPPERS) $(AM_LDFLAGS)
test_cppflags = $(AM_CPPFLAGS) $(COMMON_CPPFLAGS) -I$(top_srcdir)/client/src -I$(top_srcdir)/common/src
fabtest_cppflags = $(AM_CPPFLAGS) $(COMMON_CPPFLAGS) $(LIBFABRIC_CFLAGS) -I$(top_srcdir)/client/src -I$(top_srcdir)/common/src 


test_write_gotcha_SOURCES = test_write.c
test_write_gotcha_CPPFLAGS = $(test_cppflags)
test_write_gotcha_LDADD   = $(test_gotcha_ldadd)
test_write_gotcha_LDFLAGS = $(AM_LDFLAGS)

test_read_gotcha_SOURCES = test_read.c
test_read_gotcha_CPPFLAGS = $(test_cppflags)
test_read_gotcha_LDADD   = $(test_gotcha_ldadd)
test_read_gotcha_LDFLAGS = $(AM_LDFLAGS)

test_prw_gotcha_SOURCES = test_prw.c
test_prw_gotcha_CPPFLAGS = $(test_cppflags)
test_prw_gotcha_LDADD   = $(test_gotcha_ldadd)
test_prw_gotcha_LDFLAGS = $(AM_LDFLAGS)

test_write_static_SOURCES = test_write.c
test_write_static_CPPFLAGS = $(test_cppflags)
test_write_static_LDADD   = $(test_static_ldadd)
test_write_static_LDFLAGS = $(test_static_ldflags)

test_read_static_SOURCES = test_read.c
test_read_static_CPPFLAGS = $(test_cppflags)
test_read_static_LDADD   = $(test_static_ldadd)
test_read_static_LDFLAGS = $(test_static_ldflags)

test_prw_static_SOURCES = test_prw.c
test_prw_static_CPPFLAGS = $(test_cppflags)
test_prw_static_LDADD   = $(test_static_ldadd)
test_prw_static_LDFLAGS = $(test_static_ldflags)

fabtest_SOURCES = fabtest.c
fabtest_CPPFLAGS = $(fabtest_cppflags)
fabtest_LDADD   = $(test_static_ldadd)
fabtest_LDFLAGS = $(test_static_ldflags) -latomic -lzhpeq_util_fab -lzhpeq_util -luuid
