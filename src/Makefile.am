ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = sagan_ng
                               sagan_ng_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       sagan_ng_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               sagan_ng_SOURCES = sagan-ng.c \
						       credits.c \
						       help.c \
                                                       util.c \
						       lockfile.c \
						       signal-handler.c \
						       batch.c \
						       processor.c \
                                                       util-strlcpy.c \
                                                       util-strlcat.c \
                                                       config-yaml.c \
						       classifications.c \
						       rules.c \
						       output.c \
					               parsers/json.c \
						       parsers/search.c \
						       parsers/pcre.c \
                                                       parsers/strstr-asm/strstr-hook.c \
                                                       parsers/strstr-asm/strstr_sse2.S \
                                                       parsers/strstr-asm/strstr_sse4_2.S \
						       input-plugins/named-pipe.c \
						       output-plugins/file.c \
						       processors/engine.c

                                                       install-data-local:

