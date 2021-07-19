include $(TOPDIR)/make/common.mk

SRCDIR = cJSON
PREFIX := cJSON_

LOCAL_CFLAGS := -I$(SRCDIR)

SRCS = $(SRCDIR)/cJSON.c
OBJS = $(SRCS:.c=.o)

all: $(OBJS)

clean:
	@rm -f $(OBJS)

.PHONY: clean
