# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# contrib/fedora/passt.spec - Example spec file for fedora
#
# Copyright (c) 2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

Name:		passt
Version:	{{{ git_version }}}
Release:	1%{?dist}
Summary:	User-mode networking daemons for virtual machines and namespaces
License:	AGPLv3+ and BSD
Group:		System Environment/Daemons
URL:		https://passt.top/
Source:		https://passt.top/passt/snapshot/passt-{{{ git_head }}}.tar.xz

BuildRequires:	gcc, make, checkpolicy, selinux-policy-devel

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
Requires:   %{name} = %{version}
Requires(post): policycoreutils, %{name}
Requires(preun): policycoreutils, %{name}

%description selinux
This package adds SELinux enforcement to passt(1) and pasta(1).

%prep
%setup -q -n passt-{{{ git_head }}}

%build
%set_build_flags
%make_build

%install
%if 0%{?suse_version} > 910
%make_install DESTDIR=%{buildroot} prefix=%{_prefix} docdir=%{_prefix}/share/doc/packages/passt
%else
%make_install DESTDIR=%{buildroot} prefix=%{_prefix}
%endif
%ifarch x86_64
ln -sr %{buildroot}%{_mandir}/man1/passt.1 %{buildroot}%{_mandir}/man1/passt.avx2.1
ln -sr %{buildroot}%{_mandir}/man1/pasta.1 %{buildroot}%{_mandir}/man1/pasta.avx2.1
%endif

pushd contrib/selinux
make -f %{_datadir}/selinux/devel/Makefile
install -p -m 644 -D passt.pp %{buildroot}%{_datadir}/selinux/packages/%{name}/passt.pp
install -p -m 644 -D pasta.pp %{buildroot}%{_datadir}/selinux/packages/%{name}/pasta.pp
popd

%post selinux
semodule -i %{_datadir}/selinux/packages/%{name}/passt.pp 2>/dev/null || :
semodule -i %{_datadir}/selinux/packages/%{name}/pasta.pp 2>/dev/null || :

%preun selinux
semodule -r passt 2>/dev/null || :
semodule -r pasta 2>/dev/null || :

%files
%license LICENSES/{AGPL-3.0-or-later.txt,BSD-3-Clause.txt}
%doc %{_docdir}/passt/README.md
%doc %{_docdir}/passt/demo.sh
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
%{_datadir}/selinux/packages/%{name}/passt.pp
%{_datadir}/selinux/packages/%{name}/pasta.pp

%changelog
{{{ passt_git_changelog }}}
