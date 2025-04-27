obj-m += mynetmod.o

PWD = /home/pavletsov21/eltex/knm/kern-module/

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean_km:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean