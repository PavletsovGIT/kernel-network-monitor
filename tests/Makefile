CC = gcc
CFLAGS = -Wall

.PHONY: all, client, server, clean

all: client server

echo_client.o: echo_client.c
	$(CC) $(CFLAGS) -c echo_client.c

echo_server.o: echo_server.c
	$(CC) $(CFLAGS) -c echo_server.c

client: echo_client.o
	$(CC) $(CFLAGS) echo_client.o -o client.out

server: echo_server.o
	$(CC) $(CFLAGS) echo_server.o -o server.out

clean:
	rm -rf *.o *.out