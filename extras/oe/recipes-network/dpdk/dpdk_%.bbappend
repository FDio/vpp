# Разрешаем сборку dpdk для qemux86-64
COMPATIBLE_MACHINE:qemux86-64 = "qemux86-64"

python () {
    if d.getVar("COMPATIBLE_MACHINE") == "null":
        bb.warn("Overriding COMPATIBLE_MACHINE='null' for dpdk on qemux86-64")
}
