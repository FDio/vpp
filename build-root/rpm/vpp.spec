%define _vpp_install_dir ../install-vpp-native
%define _vpp_build_dir   ../build-tool-native
%define _unitdir         /lib/systemd/system
%define _topdir          %(pwd)
%define _builddir        %{_topdir}
%define _version         %(../scripts/version rpm-version)
%define _release         %(../scripts/version rpm-release)

Name: vpp
Summary: Vector Packet Processing
License: MIT
Version: %{_version}
Release: %{_release}
Requires: vpp-lib = %{_version}-%{_release}, net-tools, pciutils

%description
This package provides VPP executables: vpp, vpp_api_test, vpp_json_test
vpp - the vector packet engine
vpp_api_test - vector packet engine API test tool
vpp_json_test - vector packet engine JSON test tool

%package lib
Summary: VPP libraries
Group: System Environment/Libraries

%description lib
This package contains the VPP shared libraries, including:
vppinfra - foundation library supporting vectors, hashes, bitmaps, pools, and string formatting.
dpdk - Intel DPDK library
svm - vm library
vlib - vector processing library
vlib-api - binary API library
vnet -  network stack library

%package devel
Summary: VPP header files, static libraries
Group: Development/Libraries
Requires: vpp-lib

%description devel
This package contains the header files and static libraries for
vppinfra.  Install this package if you want to write or compile a
program that needs vpp.
Do we need to list those header files or just leave it blank ? 
dynamic vectors (vec.c), dynamic bitmaps (bitmap.h), allocation heap of
objects (heap.c), allocation pool(pool.h), dynamic hash tables (hash.c), memory
allocator (mheap.c), extendable printf-like interface built on top of vectors
(format.c), formats for data structures (std-formats.c), and support for clock
time-based function calls (timer.c).
TODO: reference and describe only the .h files

%install
#
# binaries
#
mkdir -p -m755 %{buildroot}%{_bindir}
mkdir -p -m755 %{buildroot}%{_unitdir}
install -p -m 755 %{_vpp_install_dir}/*/bin/* %{buildroot}%{_bindir}
install -p -m 755 %{_vpp_build_dir}/vppapigen/vppapigen %{buildroot}%{_bindir}
#
# configs
#
mkdir -p -m755 %{buildroot}/etc/vpp
mkdir -p -m755 %{buildroot}/etc/sysctl.d
install -p -m 644 vpp.service %{buildroot}%{_unitdir}
install -p -m 644 ../../vpp/conf/startup.conf %{buildroot}/etc/vpp
install -p -m 644 ../../vpp/conf/80-vpp.conf %{buildroot}/etc/sysctl.d
#
# libraries
#
mkdir -p -m755 %{buildroot}%{_libdir}
for file in $(find %{_vpp_install_dir}/*/lib* -type f -name '*.so.*.*.*' -print )
do
	install -p -m 755 $file %{buildroot}%{_libdir}
done
for file in $(cd %{buildroot}%{_libdir} && find . -type f -print | sed -e 's/^\.\///')
do
	# make lib symlinks
	( cd %{buildroot}%{_libdir} && 
          ln -fs $file $(echo $file | sed -e 's/\(\.so\.[0-9]\+\).*/\1/') )
done
#
# devel
#
for dir in $(find %{_vpp_install_dir}/*/include/ -maxdepth 0 -type d -print | grep -v dpdk)
do
	for subdir in $(cd ${dir} && find . -type d -print)
	do
		mkdir -p -m755 %{buildroot}/usr/include/${subdir}
	done
	for file in $(cd ${dir} && find . -type f -print)
	do
		install -p -m 644 $dir/$file %{buildroot}%{_includedir}/$file
	done
done
# sample plugin
mkdir -p -m755 %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/sample
for file in $(cd %{_vpp_install_dir}/../../sample-plugin && find -type f -print)
do
	install -p -m 644 %{_vpp_install_dir}/../../sample-plugin/$file \
	   %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/$file
done

%post
sysctl --system
%systemd_post vpp.service

%postun
%systemd_postun_with_restart vpp.service

%files
%defattr(-,bin,bin)
%{_unitdir}/vpp.service
/usr/bin/vpp*
/usr/bin/svm*
%config /etc/sysctl.d/80-vpp.conf
%config /etc/vpp/startup.conf

%files lib
%defattr(-,bin,bin)
%{_libdir}/*

%files devel
%defattr(-,bin,bin)
/usr/bin/vppapigen
%{_includedir}/*
/usr/share/doc/vpp/examples/sample-plugin
