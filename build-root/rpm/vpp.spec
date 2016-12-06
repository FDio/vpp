%define _mu_build_dir    %{_mu_build_root_dir}
%define _vpp_install_dir %{_install_dir}
%define _vpp_build_dir   build-tool-native
%define _unitdir         /lib/systemd/system
%define _topdir          %(pwd)
%define _builddir        %{_topdir}
%define _version         %(../scripts/version rpm-version)
%define _release         %(../scripts/version rpm-release)

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
License: MIT
Version: %{_version}
Release: %{_release}
Requires: vpp-lib = %{_version}-%{_release}, net-tools, pciutils, python
BuildRequires: systemd

Source: %{name}-%{_version}-%{_release}.tar.gz

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
dpdk - DPDK library
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

%package python-api
Summary: VPP api python bindings
Group: Development/Libraries
Requires: vpp = %{_version}-%{_release}, vpp-lib = %{_version}-%{_release}, python-setuptools

%description python-api
This package contains the python bindings for the vpp api

%prep
%setup -q -n %{name}-%{_version}

%build
make bootstrap
make build-release

%pre
# Add the vpp group
groupadd -f -r vpp

%install
#
# binaries
#
mkdir -p -m755 %{buildroot}%{_bindir}
mkdir -p -m755 %{buildroot}%{_unitdir}
install -p -m 755 %{_mu_build_dir}/%{_vpp_install_dir}/*/bin/* %{buildroot}%{_bindir}
install -p -m 755 %{_mu_build_dir}/%{_vpp_build_dir}/vppapigen/vppapigen %{buildroot}%{_bindir}

# core api
mkdir -p -m755 %{buildroot}/usr/share/vpp/api
install -p -m 755 %{_mu_build_dir}/%{_vpp_install_dir}/vpp/vpp-api/vpe.api.json %{buildroot}/usr/share/vpp/api
install -p -m 755 %{_mu_build_dir}/%{_vpp_install_dir}/vlib-api/vlibmemory/memclnt.api.json %{buildroot}/usr/share/vpp/api

#
# configs
#
mkdir -p -m755 %{buildroot}/etc/vpp
mkdir -p -m755 %{buildroot}/etc/sysctl.d
install -p -m 644 %{_mu_build_dir}/rpm/vpp.service %{buildroot}%{_unitdir}
install -p -m 644 %{_mu_build_dir}/../vpp/conf/startup.uiopcigeneric.conf %{buildroot}/etc/vpp/startup.conf
install -p -m 644 %{_mu_build_dir}/../vpp/conf/80-vpp.conf %{buildroot}/etc/sysctl.d
#
# libraries
#
mkdir -p -m755 %{buildroot}%{_libdir}
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
for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/vnet -type f -name '*.api.json' -print )
do
	install -p -m 644 $file %{buildroot}/usr/share/vpp/api
done

# Python bindings
mkdir -p -m755 %{buildroot}%{python2_sitelib}
install -p -m 666 %{_mu_build_dir}/%{_vpp_install_dir}/*/lib/python2.7/site-packages/vpp_papi-*.egg %{buildroot}%{python2_sitelib}

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
install -p -m755 %{_mu_build_dir}/../vpp-api/java/jvpp/gen/jvpp_gen.py %{buildroot}/usr/bin
for i in $(ls %{_mu_build_dir}/../vpp-api/java/jvpp/gen/jvppgen/*.py); do
   install -p -m666 ${i} %{buildroot}%{python2_sitelib}/jvppgen
done;

# sample plugin
mkdir -p -m755 %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/sample
for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/../../sample-plugin && find -type f -print)
do
	install -p -m 644 %{_mu_build_dir}/%{_vpp_install_dir}/../../sample-plugin/$file \
	   %{buildroot}/usr/share/doc/vpp/examples/sample-plugin/$file
done


#
# vpp-plugins
# 
mkdir -p -m755 %{buildroot}/usr/lib/vpp_plugins
mkdir -p -m755 %{buildroot}/usr/lib/vpp_api_test_plugins
for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/plugins/lib64/vpp_plugins && find -type f -print)
do
        install -p -m 644 %{_mu_build_dir}/%{_vpp_install_dir}/plugins/lib64/vpp_plugins/$file \
           %{buildroot}/usr/lib/vpp_plugins/$file
done

for file in $(cd %{_mu_build_dir}/%{_vpp_install_dir}/plugins/lib64/vpp_api_test_plugins && find -type f -print)
do
        install -p -m 644 %{_mu_build_dir}/%{_vpp_install_dir}/plugins/lib64/vpp_api_test_plugins/$file \
           %{buildroot}/usr/lib/vpp_api_test_plugins/$file
done

for file in $(find %{_mu_build_dir}/%{_vpp_install_dir}/plugins -type f -name '*.api.json' -print )
do
	install -p -m 644 $file %{buildroot}/usr/share/vpp/api
done

%post
sysctl --system
%systemd_post vpp.service

%post python-api
easy_install -z %{python2_sitelib}/vpp_papi-*.egg

%preun
%systemd_preun vpp.service

%preun python-api
easy_install -mxNq vpp_papi

%postun
%systemd_postun

# Unbind user-mode PCI drivers
removed=
pci_dirs=`find /sys/bus/pci/drivers -type d -name igb_uio -o -name uio_pci_generic -o -name vfio-pci`
for d in $pci_dirs; do
    for f in ${d}/*; do
        [ -e "${f}/config" ] || continue
        echo 1 > ${f}/remove
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

%files
%defattr(-,bin,bin)
%{_unitdir}/vpp.service
/usr/bin/vpp*
/usr/bin/svm*
/usr/bin/elftool
%config /etc/sysctl.d/80-vpp.conf
%config /etc/vpp/startup.conf
/usr/share/vpp/api/*

%files lib
%defattr(-,bin,bin)
%exclude %{_libdir}/vpp_plugins
%exclude %{_libdir}/vpp_api_test_plugins
%{_libdir}/*
/usr/share/vpp/api/*

%files python-api
%defattr(644,root,root)
%{python2_sitelib}/vpp_papi-*.egg

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
