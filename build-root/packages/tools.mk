tools_source = src
tools_configure_args = --disable-vlib --disable-svm --disable-japi

ifneq ($(strip $(CACHE_LINE_SIZE)),)
ifeq ($(strip $(CACHE_LINE_SIZE)),64)
tools_configure_args += --with-clib-log2-cache-line-bytes=6
else
ifeq ($(strip $(CACHE_LINE_SIZE)),128)
tools_configure_args += --with-clib-log2-cache-line-bytes=7
else
ifeq ($(strip $(CACHE_LINE_SIZE)),32)
tools_configure_args += --with-clib-log2-cache-line-bytes=5
endif
endif
endif
endif

