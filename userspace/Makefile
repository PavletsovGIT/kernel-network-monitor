CC = gcc
CFLAGS = -Wall

.PHONY: all clean

all: mynetmodctl.out

mynetmodctl.out: mynetmodctl.o 
	$(CC) mynetmodctl.o -o mynetmodctl.out

mynetmodctl.o: mynetmodctl.c 
	$(CC) $(CFLAGS) -c mynetmodctl.c

clean:
	rm -rf *.o *.out