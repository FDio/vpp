from os import getenv
from cffi import FFI

ffibuilder = FFI()

ws_root = getenv("WS_ROOT") + "/"
install_path = getenv("VPP_TEST_INSTALL_PATH")
build_dir = getenv("VPP_TEST_BUILD_DIR") + "/"

print("WS_ROOT is %s" % ws_root)
print("BUILD_DIR is %s" % build_dir)
print("INSTALL_PATH is %s" % install_path)

libdirs = [
    install_path + "vpp-api/lib64",
    install_path + "vlib-api/lib64",
    install_path + "svm/lib64",
    install_path + "vppinfra/lib64",
]

with open(ws_root + "vpp-api/python/pneum/pneum.c") as c:
    with open(ws_root + "test/pneum_wrap/pneum_wrap_extra_code.c") as extra_c:
        ffibuilder.set_source(
            "pneum",
            c.read() + "\n" + extra_c.read(),
            include_dirs=[
                ws_root + "vpp-api/python/pneum",
                ws_root + "vnet",
                ws_root + "vppinfra",
                ws_root + "vlib",
                ws_root + "vlib-api",
                ws_root + "svm",
                ws_root + "vpp",
                build_dir + "vlib",
                build_dir + "vlib-api",
                build_dir + "vnet",
                build_dir + "vpp",
            ],
            extra_objects=[
                install_path + "vpp-api/lib64/libpneum.a"],
            libraries=[
                "vlibmemoryclient",
                "vlibapi",
                "svm",
                "vppinfra",
                "pthread",
                "m",
                "rt",
            ],
            library_dirs=libdirs,
            extra_link_args=["-Wl,-R" + x for x in libdirs],
        )

with open(ws_root + "vpp-api/python/pneum/pneum.h") as h:
    stripped = "typedef unsigned long uword;\n".join(
        [l for l in h if not l.startswith("#")])

with open(ws_root + "test/pneum_wrap/pneum_wrap_extra_defs.h") as extra_h:
    extradef = extra_h.read()

ffibuilder.cdef(extradef + stripped)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
