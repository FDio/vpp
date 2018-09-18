%define _install_dir	/opt/vpp/external/%(uname -m)
%define _make_args	-C ../.. DPDK_BUILD_DIR=%{_topdir}/tmp DPDK_INSTALL_DIR=%{buildroot}/%{_install_dir}

Name:		vpp-ext-deps
Version:	%{_version}
Release:	%{_release}
Summary:	VPP development package with external dependencies
License:	BSD

%description
VPP development package with external dependencies

%install
make %{_make_args} config
make %{_make_args} install

%files
%{_install_dir}
