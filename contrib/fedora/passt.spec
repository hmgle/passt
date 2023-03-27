# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# Copyright (c) 2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

%global git_hash {{{ git_head }}}
%global selinuxtype targeted

Name:		passt
Version:	{{{ git_version }}}
Release:	1%{?dist}
Summary:	User-mode networking daemons for virtual machines and namespaces
License:	AGPLv3+ and BSD
Group:		System Environment/Daemons
URL:		https://passt.top/
Source:		https://passt.top/passt/snapshot/passt-%{git_hash}.tar.xz

BuildRequires:	gcc, make, checkpolicy, selinux-policy-devel
Requires:	(%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})

%description
passt implements a translation layer between a Layer-2 network interface and
native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
require any capabilities or privileges, and it can be used as a simple
replacement for Slirp.

pasta (same binary as passt, different command) offers equivalent functionality,
for network namespaces: traffic is forwarded using a tap interface inside the
namespace, without the need to create further interfaces on the host, hence not
requiring any capabilities or privileges.

%package    selinux
BuildArch:  noarch
Summary:    SELinux support for passt and pasta
Requires:   %{name} = %{version}-%{release}
Requires:   selinux-policy
Requires(post): %{name}
Requires(post): policycoreutils
Requires(preun): %{name}
Requires(preun): policycoreutils

%description selinux
This package adds SELinux enforcement to passt(1) and pasta(1).

%prep
%setup -q -n passt-%{git_hash}

%build
%set_build_flags
%make_build VERSION="%{version}-%{release}.%{_arch}"

%install
%make_install DESTDIR=%{buildroot} prefix=%{_prefix} bindir=%{_bindir} mandir=%{_mandir} docdir=%{_docdir}/%{name}
%ifarch x86_64
ln -sr %{buildroot}%{_mandir}/man1/passt.1 %{buildroot}%{_mandir}/man1/passt.avx2.1
ln -sr %{buildroot}%{_mandir}/man1/pasta.1 %{buildroot}%{_mandir}/man1/pasta.avx2.1
%endif

pushd contrib/selinux
make -f %{_datadir}/selinux/devel/Makefile
install -p -m 644 -D passt.pp %{buildroot}%{_datadir}/selinux/packages/%{name}/passt.pp
install -p -m 644 -D passt.if %{buildroot}%{_datadir}/selinux/devel/include/contrib/passt.if
install -p -m 644 -D pasta.pp %{buildroot}%{_datadir}/selinux/packages/%{name}/pasta.pp
popd

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{name}/passt.pp
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{name}/pasta.pp

%postun selinux
if [ $1 -eq 0 ]; then
	%selinux_modules_uninstall -s %{selinuxtype} passt
	%selinux_modules_uninstall -s %{selinuxtype} pasta
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%license LICENSES/{AGPL-3.0-or-later.txt,BSD-3-Clause.txt}
%dir %{_docdir}/%{name}
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/demo.sh
%{_bindir}/passt
%{_bindir}/pasta
%{_bindir}/qrap
%{_mandir}/man1/passt.1*
%{_mandir}/man1/pasta.1*
%{_mandir}/man1/qrap.1*
%ifarch x86_64
%{_bindir}/passt.avx2
%{_mandir}/man1/passt.avx2.1*
%{_bindir}/pasta.avx2
%{_mandir}/man1/pasta.avx2.1*
%endif

%files selinux
%dir %{_datadir}/selinux/packages/%{name}
%{_datadir}/selinux/packages/%{name}/passt.pp
%{_datadir}/selinux/devel/include/contrib/passt.if
%{_datadir}/selinux/packages/%{name}/pasta.pp

%changelog
{{{ passt_git_changelog }}}
