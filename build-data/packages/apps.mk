apps_source = src

ifndef BUILD_NOT_IN_TREE
  apps_configure_args = --disable-dpdk-plugin --enable-apps
else
  apps_configure_args = --disable-vlib --disable-svm --disable-papi   \
                        --disable-japi --disable-vom --enable-apps
endif

apps_CPPFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
apps_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror

