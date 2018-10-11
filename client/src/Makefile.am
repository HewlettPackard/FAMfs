lib_LTLIBRARIES = libunifycr.la libunifycr_gotcha.la

libunifycrdir = $(includedir)
libunifycr_gotchadir = $(includedir)

libunifycr_HEADERS = unifycr.h
libunifycr_la_SOURCES = \
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
  unifycr-defs.h \
  unifycr-internal.h \
  unifycr-wrap.h \
  unifycr-path_utils.c \
  uthash.h \
  utlist.h \
  lf_client.c \
  lf_client.h \
  fam_stripe.c \
  fam_stripe.h

libunifycr_la_CPPFLAGS = -I$(top_builddir)/client $(LIBFABRIC_CFLAGS)
libunifycr_la_LDFLAGS = -version-info $(LIBUNIFYCR_LT_VERSION) $(LIBFABRIC_LIBS) -lcrypto -lrt -lpthread

libunifycr_gotcha_HEADERS = unifycr.h
libunifycr_gotcha_la_SOURCES = \
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
  unifycr-defs.h \
  unifycr-internal.h \
  unifycr-wrap.h \
  unifycr-path_utils.c \
  uthash.h \
  utlist.h \
  lf_client.c \
  lf_client.h \
  fam_stripe.c \
  fam_stripe.h

libunifycr_gotcha_la_CPPFLAGS = -DUNIFYCR_GOTCHA -I$(top_builddir)/client $(GOTCHA_CFLAGS) $(LIBFABRIC_CFLAGS)
libunifycr_gotcha_la_LDFLAGS = -version-info $(LIBUNIFYCR_LT_VERSION) $(GOTCHA_LDFLAGS) $(LIBFABRIC_LIBS) -lgotcha -lcrypto -lrt -lpthread

