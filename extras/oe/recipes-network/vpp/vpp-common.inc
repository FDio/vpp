SRC_URI = "git://github.com/FDio/vpp.git;protocol=https;branch=master"
SRCREV = "b386cbb0650de044100332f93aa987c26ecfd784"
VPP_BASE_TAG = "v25.06-rc0"
PV = "${VPP_BASE_TAG}+git${@d.getVar('SRCREV')[0:8]}"

PR = "r0"

S = "${WORKDIR}/git"
