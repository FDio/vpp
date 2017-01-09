%define _make_args	-C ../.. DPDK_BUILD_DIR=%{_topdir}/tmp DPDK_INSTALL_DIR=%{buildroot}/usr

Name:		vpp-dpdk
Version:	%{_version}
Release:	%{_release}
Summary:	DPDK development packages for VPP
License:	BSD

%description

%package devel
Summary: 	DPDK development package for VPP
Group: 		Development/Libraries

%description devel

%install
make %{_make_args} config
make %{_make_args} install

%files devel
/usr/bin/*
/usr/include/dpdk
/usr/lib/*
/usr/sbin/*
/usr/share/dpdk
