common_CFLAGS  = -Wall -Wpedantic
common_CFLAGS += -std=gnu11
common_CFLAGS += -O2 -g
if BACKTRACE_ENABLED
common_CFLAGS += -DBACKTRACE_ENABLED -rdynamic
endif

bin_PROGRAMS = barry barry-delta

barry_SOURCES = main.c

barry_SOURCES += alloc.c alloc.h
barry_SOURCES += asn1.c asn1.h
barry_SOURCES += cer.c cer.h
barry_SOURCES += crl.c crl.h
barry_SOURCES += csv.c csv.h
barry_SOURCES += ext.c ext.h
barry_SOURCES += field.c field.h
barry_SOURCES += file.c file.h
barry_SOURCES += keys.c keys.h
barry_SOURCES += keyval.c keyval.h
barry_SOURCES += mft.c mft.h
barry_SOURCES += oid.c oid.h
barry_SOURCES += print.c print.h
barry_SOURCES += roa.c roa.h
barry_SOURCES += rpki_object.c rpki_object.h
barry_SOURCES += rpki_tree.c rpki_tree.h
barry_SOURCES += rpp.c rpp.h
barry_SOURCES += rrdp.c rrdp.h
barry_SOURCES += sha.c sha.h
barry_SOURCES += signature.c signature.h
barry_SOURCES += so.c so.h
barry_SOURCES += str.c str.h
barry_SOURCES += tal.c tal.h
barry_SOURCES += uthash.h

barry_CFLAGS = ${common_CFLAGS}
barry_LDADD  = ${common_LDADD} -lasn1fort

barry_delta_SOURCES = delta.c delta.h
barry_delta_SOURCES += alloc.c alloc.h
barry_delta_SOURCES += file.c file.h
barry_delta_SOURCES += sha.c sha.h
barry_delta_SOURCES += print.c print.h

barry_delta_CFLAGS = ${common_CFLAGS} ${XML2_CFLAGS}
barry_delta_LDADD  = ${XML2_LIBS}
