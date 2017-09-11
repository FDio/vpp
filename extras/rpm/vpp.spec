%bcond_without aesni
%define _vpp_build_dir   build-tool-native
%define _unitdir         /lib/systemd/system
%define _topdir          %(pwd)
%define _builddir        %{_topdir}
%define _mu_build_dir    %{_topdir}/%{name}-%{_version}/build-root
%define _vpp_tag	 %{getenv:TAG}
%if "%{_vpp_tag}" == ""
%define _vpp_tag	 vpp
%endif
%define _vpp_install_dir install-%{_vpp_tag}-native

# Failsafe backport of Python2-macros for RHEL <= 6
%{!?python_sitelib: %global python_sitelib      %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch:    %global python_sitearch     %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%{!?python_version: %global python_version      %(%{__python} -c "import sys; sys.stdout.write(sys.version[:3])")}
%{!?__python2:      %global __python2       %{__python}}
%{!?python2_sitelib:    %global python2_sitelib     %{python_sitelib}}
%{!?python2_sitearch:   %global python2_sitearch    %{python_sitearch}}
%{!?python2_version:    %global python2_version     %{python_version}}

%{!?python2_minor_version: %define python2_minor_version %(%{__python} -c "import sys ; print sys.version[2:3]")}

%{?systemd_requires}

Name: vpp
Summary: Vector Packet Processing
License: ASL 2.0
Version: %{_version}
Release: %{_release}
Requires: vpp-lib = %{_version}-%{_release}, net-tools, pciutils, python
BuildRequires: systemd, chrpath
%if 0%{?fedora} >= 26
BuildRequires: compat-openssl10-devel
BuildRequires: python2-devel, python2-virtualenv
%else
%if 0%{?fedora} == 25
BuildRequires: openssl-devel
BuildRequires: python-devel, python2-virtualenv
%else
BuildREquires: openssl-devel
BuildRequires: python-devel, python-virtualenv
%endif
%endif
BuildRequires: libffi-devel
BuildRequires: glibc-static, java-1.8.0-openjdk, java-1.8.0-openjdk-devel yum-utils, redhat-lsb
BuildRequires: apr-devel
%if %{with aesni}
BuildRequires: nasm
%endif
BuildRequires: numactl-devel
BuildRequires: autoconf automake libtool byacc bison flex

Source: %{name}-%{_version}-%{_release}.tar.xz
# Source: vpp-latest.tar.xz

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
svm - vm library
vlib - vector processing library
vlib-api - binary API library
vnet -  network stack library

%package devel
Summary: VPP header files, static libraries
Group: Development/Libraries
Requires: vpp-lib

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
Summary: Vector Packet Processing--runtime plugins
Group: System Environment/Libraries
Requires: vpp = %{_version}-%{_release}
%description plugins
This package contains VPP plugins

%package api-lua
Summary: VPP api lua bindings
Group: Development/Libraries
Requires: vpp = %{_version}-%{_release}, vpp-lib = %{_version}-%{_release}

%description api-lua
This package contains the lua bindings for the vpp api

%package api-java
Summary: VPP api java bindings
Group: Development/Libraries
Requires: vpp = %{_version}-%{_release}, vpp-lib = %{_version}-%{_release}

%description api-java
This package contains the java bindings for the vpp api

%package api-python
Summary: VPP api python bindings
Group: Development/Libraries
Requires: vpp = %{_version}-%{_release}, vpp-lib = %{_version}-%{_release}, python-setuptools libffi-devel

%description api-python
This package contains the python bindings for the vpp api

%prep
%setup -q -n %{name}-%{_version}

%pre
# Add the vpp group
groupadd -f -r vpp

%build
%if %{with aesni}
    make bootstrap
    make -C build-root PLATFORM=vpp TAG=%{_vpp_tag} install-packages
%else
    make bootstrap AESNI=n
    make -C build-root PLATFORM=vpp AESNI=n TAG=%{_vpp_tag} install-packages
%endif
cd %{_mu_build_dir}/../src/vpp-api/python && %py2_build

%install
#
# binaries
#
mkdir -p -m755 %{buildroot}%{_bindir}
mkdir -p -m755 %{buildroot}%{_unitdir}
install -p -m 755 %{_mu_build_dir}/%{_vpp_install_dir}/vpp/bin/* %{buildroot}%{_bindir}

# api
mkdir -p -m755 %{buildroot}/usr/share/vpp/api

#
# configs
#
mkdir -p -m755 %{buildroot}/etc/vpp
mkdir -p -m755 %{buildroot}/etc/sysctl.d
install -p -m 644 %{_mu_build_dir}/../extras/rpm/vpp.service %{buildroot}%{_unitdir}
install -p -m 644 %{_mu_build_dir}/../src/vpp/conf/startup.conf %{buildroot}/etc/vpp/startup.conf
install -p -m 644 %{_mu_build_dir}/../src/vpp/conf/80-vpp.conf %{buildroot}/etc/sysctl.d
#
# libraries
#
mkdir -p -m755 %{buildroot}%{_libdir}
mkdir -p -m755 %{buildroot}/etc/bash_completion.d
mkdir -p -m755 %{buildroot}/usr/share/vpp
for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/*/lib* -type f -name '*.so.*.*.*' -print )
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
for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/vpp/share/vpp/api  -type f -name '*.api.json' -print )
do
	install -p -m 644 $file %{buildroot}/usr/share/vpp/api
done
install -p -m 644 %{_mu_build_dir}/../src/scripts/vppctl_completion %{buildroot}/etc/bash_completion.d
install -p -m 644 %{_mu_build_dir}/../src/scripts/vppctl-cmd-list %{buildroot}/usr/share/vpp

# Lua bindings
mkdir -p -m755 %{buildroot}/usr/share/doc/vpp/examples/lua/examples/cli
mkdir -p -m755 %{buildroot}/usr/share/doc/vpp/examples/lua/examples/lute
# for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/vpp-api/lua && git ls-files .)
for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/vpp-api/lua && find . -type f -regex '.*/*.[luteamd]' -print | sed -e 's/^\.\///')
do
	( cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/vpp-api/lua && install -p -m 644 $file \
	   %{buildroot}/usr/share/doc/vpp/examples/lua/$file )
done

# Java bindings
mkdir -p -m755 %{buildroot}/usr/share/java
for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/vpp/share/java -type f -name '*.jar' -print )
do
	install -p -m 644 $file %{buildroot}/usr/share/java
done

# Python bindings
cd %{_mu_build_dir}/../src/vpp-api/python && %py2_install

#
# devel
#
for dir in $(find %{_mu_build_dir}/%{_vpp_install_dir}/*/include/ -maxdepth 0 -type d -print | grep -v dpdk)
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

mkdir -p -m755 %{buildroot}%{python2_sitelib}/jvppgen
install -p -m755 %{_mu_build_dir}/../src/vpp-api/java/jvpp/gen/jvpp_gen.py %{buildroot}/usr/bin
for i in $(ls %{_mu_build_dir}/../src/vpp-api/java/jvpp/gen/jvppgen/*.py); do
   install -p -m666 ${i} %{buildroot}%{python2_sitelib}/jvppgen
done;

# sample plugin
mkdir -p -m755 %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/sample
#for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/examples/sample-plugin && git ls-files .)
for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/examples/sample-plugin && find . -type f -regex '.*/*.[acdhimp]' -print | sed -e 's/^\.\///')
do
	( cd %{_mu_build_dir}/%{_vpp_install_dir}/../../src/examples/sample-plugin && install -p -m 644 $file \
	   %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/$file )
done


#
# vpp-plugins
# 
mkdir -p -m755 %{buildroot}/usr/lib/vpp_plugins
mkdir -p -m755 %{buildroot}/usr/lib/vpp_api_test_plugins
for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/vpp/lib64/vpp_plugins && find -type f -print)
do
        install -p -m 644 %{_mu_build_dir}/%{_vpp_install_dir}/vpp/lib64/vpp_plugins/$file \
           %{buildroot}/usr/lib/vpp_plugins/$file
done

for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/vpp/lib64/vpp_api_test_plugins && find -type f -print)
do
        install -p -m 644 %{_mu_build_dir}/%{_vpp_install_dir}/vpp/lib64/vpp_api_test_plugins/$file \
           %{buildroot}/usr/lib/vpp_api_test_plugins/$file
done

for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/plugins -type f -name '*.api.json' -print )
do
	install -p -m 644 $file %{buildroot}/usr/share/vpp/api
done

#
# remove RPATH from ELF binaries
#
%{_mu_build_dir}/scripts/remove-rpath %{buildroot}

%post
if [ $1 -eq 1 ] ; then
    sysctl --system
fi
%systemd_post vpp.service

%preun
%systemd_preun vpp.service

%postun
%systemd_postun
if [ $1 -eq 0 ] ; then
    echo "Uninstalling, unbind user-mode PCI drivers"
    # Unbind user-mode PCI drivers
    removed=
    pci_dirs=`find /sys/bus/pci/drivers -type d -name igb_uio -o -name uio_pci_generic -o -name vfio-pci`
    for d in $pci_dirs; do
        for f in ${d}/*; do
            [ -e "${f}/config" ] || continue
            echo ${f##*/} > ${d}/unbind
            basename `dirname ${f}` | xargs echo -n "Removing driver"; echo " for PCI ID" `basename ${f}`
            removed=y
        done
    done
    if [ -n "${removed}" ]; then
        echo "There are changes in PCI drivers, rescaning"
        echo 1 > /sys/bus/pci/rescan
    else
        echo "There weren't PCI devices binded"
    fi
else
    echo "Upgrading package, dont' unbind interfaces"
fi

%files
%defattr(-,bin,bin)
%{_unitdir}/vpp.service
/usr/bin/vpp*
/usr/bin/svm*
/usr/bin/elftool
%config(noreplace) /etc/sysctl.d/80-vpp.conf
%config(noreplace) /etc/vpp/startup.conf
/usr/share/vpp/api/*

%files lib
%defattr(-,bin,bin)
%exclude %{_libdir}/vpp_plugins
%exclude %{_libdir}/vpp_api_test_plugins
%{_libdir}/*
/usr/share/vpp/api/*
/etc/bash_completion.d/vppctl_completion
/usr/share/vpp/vppctl-cmd-list

%files api-lua
%defattr(644,root,root,644)
/usr/share/doc/vpp/examples/lua

%files api-java
%defattr(644,root,root)
/usr/share/java/*

%files api-python
%defattr(644,root,root)
%{python2_sitelib}/vpp_papi*

%files devel
%defattr(-,bin,bin)
/usr/bin/vppapigen
/usr/bin/jvpp_gen.py
%{_includedir}/*
%{python2_sitelib}/jvppgen/*
/usr/share/doc/vpp/examples/sample-plugin

%files plugins
%defattr(-,bin,bin)
/usr/lib/vpp_plugins/*
/usr/lib/vpp_api_test_plugins/*
/usr/share/vpp/api/*
