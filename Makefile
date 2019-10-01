# Build rules
#  `make` -- build shared library
#  `make check` -- build and run tests

CC ?= gcc
CFLAGS ?=

MAJOR_VERSION ?= 0
MINOR_VERSION ?= 0
MAINT_VERSION ?= 0

VERSION := $(MAJOR_VERSION).$(MINOR_VERSION).$(MAINT_VERSION)

LIB_FILE := librtring.so.$(VERSION)
LIB_SONAME := librtring.so.$(MAJOR_VERSION)

TEST_NAMES := test-mirror-buffer test-state-change test-latency

all: $(LIB_SONAME) $(LIB_FILE) $(TEST_NAMES)

$(LIB_FILE): rtring.c rtring.h
	$(CC) -shared -fPIC -Wl,-soname,$(LIB_SONAME) -o $(LIB_FILE) $(CFLAGS) $^ -lrtpi -lpthread -lc

$(LIB_SONAME): $(LIB_FILE)
	ln -sf $< $@

test-%: test-%.c $(LIB_SONAME)
	$(CC) -o $@ $(CFLAGS) $^ -lrtpi -lpthread -lc

check: $(TEST_NAMES)
	./run-tests.sh $^

clean:
	rm -f $(LIB_SONAME) $(LIB_FILE) $(TEST_NAMES)
