# SPDX-FileCopyrightText: Your Organization
#
# SPDX-License-Identifier: Apache-2.0

SUMMARY = "Vector Packet Processing (VPP)"
DESCRIPTION = "High-performance packet processing stack for NFV and routing."
HOMEPAGE = "https://fd.io"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://../LICENSE;md5=175792518e4ac015ab6696d16c4f607e"

require  vpp-common.inc
SRC_URI += "file://vpp-startup.conf \
            file://vpp.service \
            "

S = "${WORKDIR}/git/src"

DEPENDS = "openssl libpcap ninja-native cmake-native"

inherit pkgconfig cmake systemd useradd

EXTRA_OECMAKE = "-DVPP_BUILD_PYTHON_API=OFF"

PACKAGECONFIG ??= "dpdk"
PACKAGECONFIG[dpdk] = "-DVPP_USE_DPDK=ON -DVPP_USE_SYSTEM_DPDK=ON,-DVPP_USE_DPDK=OFF -DVPP_USE_SYSTEM_DPDK=OFF,dpdk"


do_install:append() {
        install -d ${D}${sysconfdir}/vpp
        install -d ${D}${systemd_system_unitdir}

        install -m 0644 ${WORKDIR}/vpp-startup.conf ${D}${sysconfdir}/vpp/startup.conf
        install -m 0644 ${WORKDIR}/vpp.service ${D}${systemd_system_unitdir}/vpp.service
        sed -i 's|@BINDIR@|${bindir}|g' ${D}${systemd_system_unitdir}/vpp.service
}

USERADD_PACKAGES = "${PN}"
USERADD_PARAM:${PN} = "--system --no-create-home --shell /bin/false vpp"

SYSTEMD_SERVICE:${PN} = "vpp.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

PACKAGES =+ "${PN}-config"
FILES:${PN}-config = "\
    ${sysconfdir}/vpp/startup.conf \
    ${systemd_system_unitdir}/vpp.service \
"
RDEPENDS:${PN}-config = "${PN}"

FILES:${PN} += "\
    ${bindir}/* \
    ${libdir}/* \
    ${includedir}/* \
    ${datadir}/* \
    ${sysconfdir}/* \
    ${systemd_system_unitdir}/* \
"
