include $(TOPDIR)/make/common.mk

SRCDIR = libsodium/src/libsodium
PREFIX := libsodium_

LOCAL_CFLAGS := -I$(SRCDIR)/include -I$(SRCDIR)/include/sodium -Iport/include/sodium

CFLAGS	:= -DCONFIGURED
CFLAGS	+= -DNATIVE_LITTLE_ENDIAN
CFLAGS	+= -DHAVE_WEAK_SYMBOLS
CFLAGS	+= -D__STDC_LIMIT_MACROS
CFLAGS	+= -D__STDC_CONSTANT_MACROS

SRCS = $(shell find $(SRCDIR) -name '*.c')
OBJS = $(SRCS:.c=.o)

all: $(OBJS)

clean:
	@rm -f $(OBJS)

.PHONY: clean
