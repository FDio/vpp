
ifeq ($($(PLATFORM)_enable_tests),yes)
vppinfra_configure_args += --enable-tests
endif

