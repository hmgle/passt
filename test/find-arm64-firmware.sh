#! /bin/sh

LOCATIONS="/usr/share/qemu-efi-aarch64 /usr/share/edk2/aarch64"

for l in $LOCATIONS; do
    if [ -f "$l/QEMU_EFI.fd" ]; then
	ln -s "$l/QEMU_EFI.fd" "$1"
	exit 0
    fi
done

echo "Couldn't find QEMU_EFI.fd" >&2
exit 1
