# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests makefile
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

DOWNLOAD_ASSETS =
LOCAL_ASSETS =

ASSETS = $(DOWNLOAD_ASSETS) $(LOCAL_ASSETS)

assets: $(ASSETS)

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
