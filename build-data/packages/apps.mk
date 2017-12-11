apps_source = src

apps_configure_args = --disable-dpdk-plugin --enable-apps

apps_CPPFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
apps_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
