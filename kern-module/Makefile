obj-m += mynetmod.o

PWD := $(shell pwd)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean_km:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean