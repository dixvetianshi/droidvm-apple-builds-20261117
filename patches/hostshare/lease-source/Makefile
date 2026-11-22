obj-m += gunyah-host-share-gki-6.6.o
gunyah-host-share-gki-6.6-y := gunyah_share_mod.o
KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: module
module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
