SUMMARY = "Vector Packet Processing (VPP)"
DESCRIPTION = "High-performance packet processing stack for NFV and routing."
HOMEPAGE = "https://fd.io"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=175792518e4ac015ab6696d16c4f607e"

require vpp-common.inc

SRC_URI += "file://0001-disable-python-api.patch \
            file://vpp-startup.conf \
            file://vpp.service"

DEPENDS = "dpdk openssl libpcap numactl \
           python3-native ninja-native cmake-native python3-ply-native"

RDEPENDS:${PN} += "bash kmod iproute2"

inherit python3native pkgconfig systemd useradd

USERADD_PACKAGES = "${PN}"
USERADD_PARAM:${PN} = "--system --no-create-home --shell /bin/false vpp"

SYSTEMD_SERVICE:${PN} = "vpp.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

INHIBIT_PACKAGE_STRIP = "1"
INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
EXTRA_OEMAKE = ""

# Disable building of external components using a dummy Makefile
do_configure() {
    mkdir -p ${S}/build/external
    cat > ${S}/build/external/Makefile << 'EOF'
.PHONY: ebuild-build ebuild-install
ebuild-build ebuild-install:
	@:
EOF
}

# Compile VPP using the native platform
do_compile() {
    cd ${S}

    export PLATFORM=native
    #export VPP_DISABLE_INSTALL_DEP=1

    export CC="${TARGET_PREFIX}gcc"
    export CXX="${TARGET_PREFIX}g++"
    export LD="${TARGET_PREFIX}ld"
    export AR="${TARGET_PREFIX}ar"
    export RANLIB="${TARGET_PREFIX}ranlib"
    export CROSS_COMPILE="${TARGET_PREFIX}"

    # Add debug prefix mapping to avoid embedding TMPDIR in binaries
    export CFLAGS="--sysroot=${STAGING_DIR_TARGET} ${TARGET_CFLAGS} \
        -fdebug-prefix-map=${WORKDIR}=/usr/src/debug/${PN}/${PV} \
        -fdebug-prefix-map=${S}=/usr/src/debug/${PN}/${PV} \
        -fmacro-prefix-map=${WORKDIR}=/usr/src/debug/${PN}/${PV} \
        -fmacro-prefix-map=${S}=/usr/src/debug/${PN}/${PV}"

    export CXXFLAGS="--sysroot=${STAGING_DIR_TARGET} ${TARGET_CXXFLAGS} \
        -fdebug-prefix-map=${WORKDIR}=/usr/src/debug/${PN}/${PV} \
        -fdebug-prefix-map=${S}=/usr/src/debug/${PN}/${PV} \
        -fmacro-prefix-map=${WORKDIR}=/usr/src/debug/${PN}/${PV} \
        -fmacro-prefix-map=${S}=/usr/src/debug/${PN}/${PV}"

    export LDFLAGS="${TARGET_LDFLAGS}"

    export PKG_CONFIG_PATH="${STAGING_DIR_TARGET}/usr/lib/pkgconfig}:${STAGING_DIR_TARGET}/usr/share/pkgconfig}"

    export CMAKE_GENERATOR="Ninja"
    export CMAKE_MAKE_PROGRAM="ninja"
    export CMAKE_INSTALL_PREFIX="/usr"

    make build-release
}

# Install VPP by copying pre-built binaries (no recompilation)
do_install() {
    local build_dir="${S}/build-root/build-native-native/vpp"

    install -d ${D}${bindir}
    install -d ${D}${libdir}/vpp
    install -d ${D}${libdir}/vat2_plugins
    install -d ${D}${includedir}
    install -d ${D}${datadir}/vpp/api
    install -d ${D}${sysconfdir}/vpp
    install -d ${D}${systemd_system_unitdir}

    # Install binaries
    cp -f ${build_dir}/bin/vpp ${D}${bindir}/
    cp -f ${build_dir}/bin/vppctl ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_api_test ${D}${bindir}/
    cp -f ${build_dir}/bin/vat2 ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_get_stats ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_get_metrics ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_json_test ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_prometheus_export ${D}${bindir}/
    cp -f ${build_dir}/bin/vpp_restart ${D}${bindir}/

    # Install shared libraries
    cp -rf ${build_dir}/lib/*.so* ${D}${libdir}/
    cp -rf ${build_dir}/lib/vpp_plugins/* ${D}${libdir}/vpp/ 2>/dev/null || true
    cp -rf ${build_dir}/lib/vat2_plugins/* ${D}${libdir}/vat2_plugins/ 2>/dev/null || true

    # Install headers and API files
    cp -rf ${build_dir}/share/vpp/api/* ${D}${datadir}/vpp/api/ 2>/dev/null || true
    cp -rf ${build_dir}/include/* ${D}${includedir}/ 2>/dev/null || true

    # Install configuration and systemd service
    install -m 0644 ${WORKDIR}/vpp-startup.conf ${D}${sysconfdir}/vpp/startup.conf
    install -m 0644 ${WORKDIR}/vpp.service ${D}${systemd_system_unitdir}/vpp.service
    sed -i 's|@BINDIR@|${bindir}|g' ${D}${systemd_system_unitdir}/vpp.service
}

# Create symbolic links for shared libraries (e.g. libvpp.so -> libvpp.so.25.10)
do_install:append() {
    for so in ${D}${libdir}/*.so.*; do
        if [ -f "$so" ] && [ ! -L "$so" ]; then
            local soname=$(basename $so)
            local short_soname=$(echo $soname | sed 's/\.so\.[0-9.]*$/.so/')
            ln -sf $soname ${D}${libdir}/$short_soname 2>/dev/null || true
        fi
    done
}

# Include all files in the main package for now (dev split disabled)
FILES:${PN} += "\
    ${bindir}/vpp \
    ${bindir}/vppctl \
    ${bindir}/vpp_api_test \
    ${bindir}/vat2 \
    ${bindir}/vpp_get_stats \
    ${bindir}/vpp_get_metrics \
    ${bindir}/vpp_json_test \
    ${bindir}/vpp_prometheus_export \
    ${bindir}/vpp_restart \
    ${libdir}/*.so* \
    ${libdir}/vpp/ \
    ${libdir}/vat2_plugins/ \
    ${includedir}/ \
    ${datadir}/vpp/api/ \
    ${sysconfdir}/vpp/ \
    ${systemd_system_unitdir}/vpp.service \
"
