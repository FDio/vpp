ifneq ($(strip ${VPP_TEST_INSTALL_PATH}),)
    CFLAGS	+= -I${VPP_TEST_INSTALL_PATH}/vpp/include
    LDFLAGS	+= -L${VPP_TEST_INSTALL_PATH}/vpp/lib64
endif

BUILD_TESTS	+= test_include_vnet_check


.PHONY: test-c-build
test-c-build: clean $(BUILD_TESTS)

test_include_vnet_check: test_include_vnet_check.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	./test_include_vnet_check

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@rm -rf test_include_vnet_check.o test_include_vnet_check
