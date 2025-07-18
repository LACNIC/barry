if USE_TESTS

# Reminder: Automake will automatically add this to any targets where
# <mumble>_CFLAGS is not defined.
# Otherwise it must be included manually:
# 	mumble_mumble_CFLAGS = ${AM_CFLAGS} flag1 flag2 flag3 ...
AM_CFLAGS = -Wall -pedantic
AM_CFLAGS += -std=gnu11
AM_CFLAGS += -DBACKTRACE_ENABLED -rdynamic
AM_CFLAGS += -I../src ${CHECK_CFLAGS}
# Needs to be manually added to every target
MY_LDADD = ${CHECK_LIBS} -lasn1fort

check_PROGRAMS  = field.test
#check_PROGRAMS += tree.test
TESTS = ${check_PROGRAMS}

field_test_SOURCES  = field_test.c
field_test_SOURCES += ../src/alloc.c ../src/alloc.h
field_test_SOURCES += ../src/asn1.c ../src/asn1.h
field_test_SOURCES += ../src/oid.c ../src/oid.h
field_test_LDADD = ${MY_LDADD}

endif
