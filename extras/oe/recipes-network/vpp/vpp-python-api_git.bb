# SPDX-License-Identifier: MIT
# Copyright (c) 2025, skbuff.ru

SUMMARY = "VPP Python API bindings"
DESCRIPTION = "Python bindings for VPP API (vpp-papi)"
HOMEPAGE = "https://fd.io"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${WORKDIR}/git/LICENSE;md5=175792518e4ac015ab6696d16c4f607e"

require vpp-common.inc

S = "${WORKDIR}/git/src/vpp-api/python"

DEPENDS = "vpp python3-native python3-setuptools-native python3-ply-native"

inherit python3native

PYTHON3 = "${STAGING_DIR_NATIVE}/usr/bin/python3-native/python3"

RDEPENDS:${PN} += "python3-core vpp"

do_compile() {
    cd ${S}
    ${PYTHON3} setup.py build
}

do_install() {
    cd ${S}
    ${PYTHON3} setup.py install --prefix=${D}/usr --root=/
}

FILES:${PN} += "/usr/lib/python*/site-packages/"
ALLOW_EMPTY:${PN} = "0"
