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

#client: tcp_client.o udp_client.o
#	$(CC) tcp_client.o -o tcp_client.out
#	$(CC) udp_client.o -o udp_client.out

#server: tcp_server.o udp_server.o
#	$(CC) tcp_server.o -o tcp_server.out
#	$(CC) udp_server.o -o udp_server.out

#tcp_client.o: tcp_client.c
#	$(CC) $(CFLAGS) -c tcp_client.c

#udp_client.o: udp_client.c
#	$(CC) $(CFLAGS) -c udp_client.c

#tcp_server.o: tcp_server.c 
#	$(CC) $(CFLAGS) -c tcp_server.c

#udp_server.o: udp_server.c 
#	$(CC) $(CFLAGS) -c udp_server.c

clean:
	rm -rf *.o *.out