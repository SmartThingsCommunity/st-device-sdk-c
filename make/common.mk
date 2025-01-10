CC = gcc
AR = ar
MV = mv

.c.o:
	@echo "  CC    $@"
	@$(CC) -c -o $@ $< $(CFLAGS) $(LOCAL_CFLAGS)
	@mv -f $@ $(dir $@)$(PREFIX)$(notdir $@)
	@mv -f $(dir $@)*.o $(BUILD_DIR)

%.a:
	@echo "  AR    $@"
	@$(AR) rcs $@ $^
