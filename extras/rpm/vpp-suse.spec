#
# spec file for package vpp
#
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


%define _vpp_build_dir       %{buildroot}/../../BUILD/vpp-%{version}/build-root
%define _vpp_install_dir     %{_vpp_build_dir}/install-vpp-native/
%define _vpp_plugins_lib_dir %{_vpp_install_dir}/vpp/lib64

%define lname libvpp0

Name:           vpp
Version:        %{_version}
Release:        %{_release}
Summary:        Set of libraries and drivers for fast packet processing
License:        Apache-2.0
Group:          Productivity/Networking/Routing
Url:            https://wiki.fd.io/view/VPP
Source0:        %{name}-%{version}-%{_release}.tar.xz
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  bison
BuildRequires:  ccache
BuildRequires:  check-devel
BuildRequires:  chrpath
BuildRequires:  distribution-release
BuildRequires:  gcc
BuildRequires:  glibc-devel-static
BuildRequires:  java-1_8_0-openjdk-devel
BuildRequires:  libnuma-devel
BuildRequires:  libopenssl-devel
BuildRequires:  libtool
BuildRequires:  lsb-release
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  python-devel
BuildRequires:  python-pip
BuildRequires:  python-rpm-macros
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  shadow
Conflicts:      otherproviders(vpp-any)
Provides:       %{name}-any = %{version}
ExclusiveArch:  x86_64 aarch64
%if 0%{?suse_version} >= 1210
BuildRequires:  systemd-rpm-macros
%endif

%description
The Vector Packet Processing platform is a framework that provides
switch/router functionality. It is based on Cisco's packet processing
stack that can run on commodity CPUs.
This package provides VPP executables: vpp, vpp_api_test, vpp_json_test
vpp - the vector packet engine
vpp_api_test - vector packet engine API test tool
vpp_json_test - vector packet engine JSON test tool

%package -n %{lname}
Summary:        VPP libraries
Group:          System/Libraries
Provides:       %{lname}-any = %{version}

%description -n %{lname}
This package contains the VPP shared libraries, including:
vppinfra - foundation library supporting vectors, hashes, bitmaps, pools, and string formatting.
svm - vm library
vlib - vector processing library
vlib-api - binary API library
vnet -  network stack library

%package devel
Summary:        VPP header files, static libraries
Group:          Development/Libraries/C and C++
Requires:       %{lname} = %{version}
Conflicts:      otherproviders(%{name}-any-devel)
Provides:       %{name}-any-devel = %{version}

%description devel
This package contains the header files for VPP.
Install this package if you want to write a
program for compilation and linking with vpp lib.
vlib
vlibmemory
vnet - devices, classify, dhcp, ethernet flow, gre, ip, etc.
vpp-api
vppinfra

%package plugins
Summary:        Vector Packet Processing--runtime plugins
Group:          Productivity/Networking/Routing
Conflicts:      otherproviders(%{name}-any-plugins)
Provides:       %{name}-any-plugins = %{version}

%description plugins
This package contains the VPP plugins which are loaded by VPP at startup

%package api-lua
Summary:        VPP api lua bindings
Group:          Development/Libraries/Other
Requires:       %{lname} = %{version}
Requires:       %{name} = %{version}
Conflicts:      otherproviders(%{name}-any-api-lua)
Provides:       %{name}-any-api-lua = %{version}

%description api-lua
This package contains the lua bindings for the vpp api

%package api-java
Summary:        VPP api java bindings
Group:          Development/Libraries/Java
Requires:       %{lname} = %{version}
Requires:       %{name} = %{version}
Conflicts:      otherproviders(%{name}-any-api-java)
Provides:       %{name}-any-api-java = %{version}

%description api-java
This package contains the java bindings for the vpp api

%package api-python
Summary:        VPP api python bindings
Group:          Development/Libraries/Python
Requires:       %{lname} = %{version}
Requires:       %{name} = %{version}
Requires:       python-setuptools
Conflicts:      otherproviders(%{name}-any-python-api)
Provides:       %{name}-any-python-api = %{version}

%description api-python
This package contains the python bindings for the vpp api

%prep
%setup -q -n %{name}-%{version}

%build
export VPP_BUILD_USER=suse
export VPP_BUILD_HOST=SUSE

make V=1 PLATFORM=vpp bootstrap
make V=1 PLATFORM=vpp build-release

cd %{_vpp_build_dir}/../src/vpp-api/python && %{py2_build}

%pre
# Add the vpp group
getent group vpp >/dev/null || groupadd -r vpp
%service_add_pre vpp.service

%install
#
# binaries
#
mkdir -p -m755 %{buildroot}%{_bindir}
mkdir -p -m755 %{buildroot}%{_unitdir}
install  -m 755 %{_vpp_install_dir}/*/bin/* %{buildroot}%{_bindir}

# api
mkdir -p -m755 %{buildroot}%{_datadir}/vpp/api

#
# core api
#
mkdir -p -m755 %{buildroot}%{_datadir}/vpp/api
install -p -m 644 %{_vpp_install_dir}/vpp/share/vpp/api/core/*.api.json %{buildroot}%{_datadir}/vpp/api
install -p -m 644 %{_vpp_install_dir}/vpp/share/vpp/api/plugins/*.api.json %{buildroot}%{_datadir}/vpp/api
#
# configs
#
mkdir -p -m755 %{buildroot}%{_sysconfdir}/vpp
mkdir -p -m755 %{buildroot}%{_sysconfdir}/sysctl.d
install -p -m 644 %{_vpp_build_dir}/../extras/rpm/vpp.service %{buildroot}%{_unitdir}
install -p -m 644 %{_vpp_build_dir}/../src/vpp/conf/startup.conf %{buildroot}%{_sysconfdir}/vpp/startup.conf
install -p -m 644 %{_vpp_build_dir}/../src/vpp/conf/80-vpp.conf %{buildroot}%{_sysconfdir}/sysctl.d
#
# libraries
#
mkdir -p -m755 %{buildroot}%{_libdir}
mkdir -p -m755 %{buildroot}%{_sysconfdir}/bash_completion.d
mkdir -p -m755 %{buildroot}%{_datadir}/vpp
for file in $(find %{_vpp_install_dir}/*/lib* -type f -name '*.so.*.*.*' -print )
do
	install -p -m 755 $file %{buildroot}%{_libdir}
done
for file in $(cd %{buildroot}%{_libdir} && find . -type f -print | sed -e 's/^\.\///')
do
	# make lib symlinks
	( cd %{buildroot}%{_libdir} &&
          ln -fs $file $(echo $file | sed -e 's/\(\.so\.[0-9]\+\).*/\1/') )
	( cd %{buildroot}%{_libdir} &&
          ln -fs $file $(echo $file | sed -e 's/\(\.so\)\.[0-9]\+.*/\1/') )
done
for file in $(find %{_vpp_install_dir}/vpp/share/vpp/api  -type f -name '*.api.json' -print )
do
        install -p -m 644 $file %{buildroot}%{_datadir}/vpp/api
done
install -p -m 644 %{_vpp_build_dir}/../src/scripts/vppctl_completion %{buildroot}%{_sysconfdir}/bash_completion.d
install -p -m 644 %{_vpp_build_dir}/../src/scripts/vppctl-cmd-list %{buildroot}%{_datadir}/vpp

# Lua bindings
mkdir -p -m755 %{buildroot}%{_datadir}/doc/vpp/examples/lua/examples/cli
mkdir -p -m755 %{buildroot}%{_datadir}/doc/vpp/examples/lua/examples/lute
for file in $(cd %{_vpp_install_dir}/../../src/vpp-api/lua && git ls-files .)
do
        install -p -m 644 %{_vpp_install_dir}/../../src/vpp-api/lua/$file \
           %{buildroot}%{_datadir}/doc/vpp/examples/lua/$file
done

# Java bindings
mkdir -p -m755 %{buildroot}%{_datadir}/java
for file in $(find %{_vpp_install_dir}/vpp/share/java -type f -name '*.jar' -print )
do
        install -p -m 644 $file %{buildroot}%{_datadir}/java
done

# Python bindings
cd %{_vpp_build_dir}/../src/vpp-api/python && %{py2_install}

mkdir -p -m755 %{buildroot}%{python_sitelib}/vpp_papi
for file in $(find %{_vpp_install_dir}/*/lib/python2.7/site-packages/ -type f -print | grep -v pyc | grep -v pyo)
do
	install -p -m755 $file %{buildroot}%{python_sitelib}/vpp_papi/
done
chmod -x %{buildroot}%{python_sitelib}/vpp_papi/*.txt

#
# devel
#
for dir in $(find %{_vpp_install_dir}/*/include/ -maxdepth 0 -type d -print | grep -v dpdk)
do
	for subdir in $(cd ${dir} && find . -type d -print)
	do
		mkdir -p -m755 %{buildroot}%{_includedir}/${subdir}
	done
	for file in $(cd ${dir} && find . -type f -print)
	do
		install -p -m 644 $dir/$file %{buildroot}%{_includedir}/$file
	done
done

mkdir -p -m755 %{buildroot}%{python_sitelib}/jvppgen
install -p -m755 %{_vpp_build_dir}/../src/vpp-api/java/jvpp/gen/jvpp_gen.py %{buildroot}%{_prefix}/bin
for i in $(ls %{_vpp_build_dir}/../src/vpp-api/java/jvpp/gen/jvppgen/*.py); do
   install -p -m755 ${i} %{buildroot}%{python_sitelib}/jvppgen
done;

# sample plugin
mkdir -p -m755 %{buildroot}%{_datadir}/doc/vpp/examples/sample-plugin/sample
for file in $(cd %{_vpp_install_dir}/../../sample-plugin && find -type f -print)
do
	install -p -m 644 %{_vpp_install_dir}/../../sample-plugin/$file \
	   %{buildroot}%{_datadir}/doc/vpp/examples/sample-plugin/$file
done

#
# vpp-plugins
#
mkdir -p -m755 %{buildroot}%{_libdir}/vpp_plugins
mkdir -p -m755 %{buildroot}%{_libdir}/vpp_api_test_plugins
for file in $(cd %{_vpp_plugins_lib_dir}/vpp_plugins && find -type f -print)
do
        install -p -m 644 %{_vpp_plugins_lib_dir}/vpp_plugins/$file \
           %{buildroot}/%{_libdir}/vpp_plugins/$file
done

for file in $(cd %{_vpp_plugins_lib_dir}/vpp_api_test_plugins && find -type f -print)
do
        install -p -m 644 %{_vpp_plugins_lib_dir}/vpp_api_test_plugins/$file \
           %{buildroot}/%{_libdir}/vpp_api_test_plugins/$file
done

for file in $(find %{_vpp_install_dir}/plugins -type f -name '*.api.json' -print )
do
        install -p -m 644 $file %{buildroot}%{_datadir}/vpp/api
done

#
# remove RPATH from ELF binaries
#
%{_vpp_build_dir}/scripts/remove-rpath %{buildroot}

export NO_BRP_CHECK_RPATH=true

%post
%service_add_post vpp.service

%post -n %{lname} -p /sbin/ldconfig

%preun
%service_del_preun vpp.service

%postun
%service_del_postun vpp.service

%postun -n %{lname} -p /sbin/ldconfig

%files
%{_unitdir}/vpp.service
%{_bindir}/vpp*
%{_bindir}/svm*
%{_bindir}/elftool
%dir %{_sysconfdir}/vpp
%config %{_sysconfdir}/sysctl.d/80-vpp.conf
%config %{_sysconfdir}/vpp/startup.conf
%{_sysconfdir}/bash_completion.d/vppctl_completion
%{_datadir}/vpp/vppctl-cmd-list
%doc LICENSE

%files -n %{lname}
%exclude %{_libdir}/vpp_plugins
%exclude %{_libdir}/vpp_api_test_plugins
%{_libdir}/*.so.*

%files api-lua
%{_datadir}/doc/vpp/examples/lua

%files api-java
%{_datadir}/java/*

%files api-python
%dir %{python_sitelib}/vpp_papi*
%{python_sitelib}/vpp_papi*

%files devel
%dir %{python_sitelib}/jvppgen
%{python_sitelib}/jvppgen/*
%dir %{_datadir}/doc/vpp
%dir %{_datadir}/doc/vpp/examples
%{_libdir}/*.so
%{_bindir}/jvpp_gen.py
%{_includedir}/*
%{_datadir}/doc/vpp/examples/sample-plugin
%dir %{_datadir}/vpp
%dir %{_datadir}/vpp/api
%{_datadir}/vpp/api/*

%files plugins
%dir %{_libdir}/vpp_plugins
%dir %{_libdir}/vpp_api_test_plugins
%{_libdir}/vpp_plugins/*.so*
%{_libdir}/vpp_api_test_plugins/*.so*

%changelog
