include $(TOPDIR)/make/common.mk

SRCDIR = curl
PREFIX := curl_

LOCAL_CFLAGS := -I$(SRCDIR)/lib -I$(SRCDIR)/include -Iport/include

CFLAGS	:= -DHAVE_CONFIG_H
CFLAGS	+= -DBUILDING_LIBCURL

SRCS = $(shell find $(SRCDIR)/lib -name '*.c')
SRCS += $(shell find $(SRCDIR)/lib/vauth -name '*.c')
SRCS += $(shell find $(SRCDIR)/lib/vtls -name '*.c')
OBJS = $(SRCS:.c=.o)

all: $(OBJS)

clean:
	@rm -f $(OBJS)

.PHONY: clean
