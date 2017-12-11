test-apps_source = src

test-apps_configure_args = --disable-dpdk-plugin --disable-japi --disable-vom --disable-vlib --disable-svm --disable-papi --enable-test-apps
test-apps_configure_depend = vpp-install
vpp_enable_test_apps = yes

test-apps_CPPFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
test-apps_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror

