CC = gcc
CFLAGS = -Wall -ansi -pedantic -std=c99
export CFLAGS

all: kernel_module userspace_apps test_apps

kernel_module:
	$(MAKE) -C kern-module -f Makefile

userspace_apps:
	$(MAKE) -C userspace -f Makefile

test_apps:
	$(MAKE) -C tests -f Makefile

clean:
	$(MAKE) -C kern-module -f Makefile clean_km
	$(MAKE) -C userspace -f Makefile clean
	$(MAKE) -C tests -f Makefile clean

load:
	sudo insmod kern-module/mynetmod.ko

unload:
	sudo rmmod mynetmod

.PHONY: all kernel_module userspace_apps test_apps clean load unload