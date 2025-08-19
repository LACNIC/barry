bin_PROGRAMS = barry

barry_SOURCES = main.c

barry_SOURCES += alloc.c alloc.h
barry_SOURCES += asn1.c asn1.h
barry_SOURCES += cer.c cer.h
barry_SOURCES += crl.c crl.h
barry_SOURCES += csv.c csv.h
barry_SOURCES += ext.c ext.h
barry_SOURCES += field.c field.h
barry_SOURCES += keyval.h
barry_SOURCES += libcrypto.c libcrypto.h
barry_SOURCES += mft.c mft.h
barry_SOURCES += oid.c oid.h
barry_SOURCES += print.c print.h
barry_SOURCES += roa.c roa.h
barry_SOURCES += rpki_object.c rpki_object.h
barry_SOURCES += rpki_tree.c rpki_tree.h
barry_SOURCES += rpp.c rpp.h
barry_SOURCES += rrdp.c rrdp.h
barry_SOURCES += so.c so.h
barry_SOURCES += str.c str.h
barry_SOURCES += tal.c tal.h
barry_SOURCES += uthash.h

barry_CFLAGS  = -Wall -Wpedantic
barry_CFLAGS += -std=gnu11
barry_CFLAGS += -O2 -g
if BACKTRACE_ENABLED
barry_CFLAGS += -DBACKTRACE_ENABLED -rdynamic
endif
barry_LDADD = -lasn1fort
