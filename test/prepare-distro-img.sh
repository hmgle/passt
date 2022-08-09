#! /bin/sh -e

IMG="$1"
PASST_FILES="$(echo ../*.c ../*.h ../*.sh ../*.1 ../Makefile ../README.md)"

virt-edit -a $IMG /lib/systemd/system/serial-getty@.service -e 's/ExecStart=.*/ExecStart=\/sbin\/agetty --autologin root -8 --keep-baud 115200,38400,9600 %I $TERM/g'

guestfish --rw -a $IMG -i <<EOF
rm-f /usr/lib/systemd/system/cloud-config.service
rm-f /usr/lib/systemd/system/cloud-init.service
rm-f /usr/lib/systemd/system/cloud-init-local.service
rm-f /usr/lib/systemd/system/cloud-final.service
rm-f /etc/init.d/cloud-config
rm-f /etc/init.d/cloud-final
rm-f /etc/init.d/cloud-init
rm-f /etc/init.d/cloud-init-local
copy-in $PASST_FILES /root/
EOF
