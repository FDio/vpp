# SRTP (Secure Real-time Transport Protocol)

libsrtp2 based SRTP transport protocol implementation.

## Maturity level
Experimental

## Quickstart

1. Install libsrtp2-dev. On debian based OS:

```
sudo apt get install libsrtp2-dev
```

2. Build vpp

```
make build
```

3. Test protocol using vcl test server and client. On server side, start vpp and server app:

```
export VT_PATH=$WS/build-root/build-vpp_debug-native/vpp/bin
$VT_PATH/vcl_test_server 1234 -p srtp
```

On client side:

```
export VT_PATH=$WS/build-root/build-vpp_debug-native/vpp/bin
$VT_PATH/vcl_test_client <server-ip> 1234 -U -X -S -N 10000 -T 128 -p srtp
```

## Custom libsrtp2 build

1. Create `build/external/packages/srtp.mk` with following example contents:

```
srtp_version := 2.3.0
srtp_tarball := srtp_$(srtp_version).tar.gz
srtp_tarball_md5sum := da38ee5d9c31be212a12964c22d7f795
srtp_tarball_strip_dirs := 1
srtp_url := https://github.com/cisco/libsrtp/archive/v$(srtp_version).tar.gz

define  srtp_build_cmds
	@cd $(srtp_build_dir) && \
		$(CMAKE) -DCMAKE_INSTALL_PREFIX:PATH=$(srtp_install_dir)	\
		-DCMAKE_C_FLAGS='-fPIC -fvisibility=hidden'  $(srtp_src_dir) > $(srtp_build_log)
	@$(MAKE) $(MAKE_ARGS) -C $(srtp_build_dir) > $(srtp_build_log)
endef

define  srtp_config_cmds
	@true
endef

define  srtp_install_cmds
	@$(MAKE) $(MAKE_ARGS) -C $(srtp_build_dir) install > $(srtp_install_log)
endef


$(eval $(call package,srtp))
```

2. Include `srtp.mk` in `build/external/Makefile` and add to install target. 

3. Rebuild external dependencies:

```
make install-ext-deps
```