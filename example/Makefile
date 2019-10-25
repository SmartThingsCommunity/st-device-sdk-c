
CC = gcc
RM = rm -rf
CFLAGS = -std=c99
LIB_NAME = iotcore
INC = -I../src/include
LIB_DIR = -L../output
LIBS = -l$(LIB_NAME) -lssl -lpthread -lrt -lcrypto
SRCS = example.c
JSONS = device_info.json onboarding_config.json
OBJS = $(JSONS:%.json=%.o)
TARGET = example
OBJCOPY_CMD = objcopy
OBJCOPY_INPUT = binary
OBJCOPY_OUTPUT = elf64-x86-64
OBJCOPY_ARCH = i386

.PHONY: all clean
all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)

%.o : %.json
	@echo $@
	$(OBJCOPY_CMD) -I $(OBJCOPY_INPUT) -O $(OBJCOPY_OUTPUT) -B $(OBJCOPY_ARCH) $< $@

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(SRCS) $(OBJS) $(LIB_DIR) $(INC) $(LIBS)
