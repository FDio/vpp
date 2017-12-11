test-apps_source = src

test-apps_configure_args = --disable-dpdk-plugin --disable-japi         \
                           --disable-vom --disable-vlib --disable-svm   \
                           --disable-papi --enable-test-apps
test-apps_configure_depend = vpp-install
