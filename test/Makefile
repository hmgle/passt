# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests makefile
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

DOWNLOAD_ASSETS = mbuto
LOCAL_ASSETS = mbuto.img QEMU_EFI.fd

ASSETS = $(DOWNLOAD_ASSETS) $(LOCAL_ASSETS)

assets: $(ASSETS)

mbuto:
	git clone git://mbuto.sh/mbuto

mbuto.img: passt.mbuto mbuto
	./mbuto/mbuto -p ./$< -c lz4 -f $@

QEMU_EFI.fd:
	./find-arm64-firmware.sh $@

check: assets
	./run

debug: assets
	DEBUG=1 ./run

clean:
	rm -f perf.js *~
	rm -f $(LOCAL_ASSETS)
	rm -rf test_logs

realclean: clean
	rm -rf $(DOWNLOAD_ASSETS)
