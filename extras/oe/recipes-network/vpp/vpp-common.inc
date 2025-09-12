SRC_URI = "git://github.com/FDio/vpp.git;protocol=https;branch=master"
SRCREV = "8e88bf52ab53db84d958f52ece4f29a76ca7e19a"
VPP_BASE_TAG = "v25.06-rc0"
PV = "${VPP_BASE_TAG}+git${@d.getVar('SRCREV')[0:8]}"

PR = "r0"

S = "${WORKDIR}/git"
