COMPATIBLE_MACHINE:qemux86-64 = "qemux86-64"

python () {
    if d.getVar("COMPATIBLE_MACHINE") == "null":
        bb.warn("Overriding COMPATIBLE_MACHINE='null' for dpdk on qemux86-64")
}

do_install:append() {
    cp ${S}/lib/eal/include/bus_driver.h ${D}${includedir}/
    cp ${S}/lib/eal/include/dev_driver.h ${D}${includedir}/
    cp ${S}/drivers/bus/pci/bus_pci_driver.h ${D}${includedir}/
    cp ${S}/drivers/bus/vmbus/bus_vmbus_driver.h ${D}${includedir}/
}
