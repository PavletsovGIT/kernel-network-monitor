#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define COMMANDS_NUM	8
#define BUF_SIZE		64
#define SA 				struct sockaddr

void die(const char *s) { perror(s); exit(1); }

int tcp_client(struct in_addr ip, int port_dst, char *msg);
int udp_client(struct in_addr ip, int port_dst, char *msg);

static int validate_port(uint16_t port);
static int validate_proto(const char *proto);
void print_usage(char *app_name);

int main(int argc, char *argv[])
{
	if (argc != COMMANDS_NUM + 1)
	{
		fprintf(stderr, "Programm needs %d arguments!\n", COMMANDS_NUM);
		exit(EXIT_FAILURE);
	}

	int port, proto;
	struct in_addr ip;
	int opt;
	int option_index = 0;
	char msg[BUF_SIZE] = {0};

	// Структура принимаемых команд
	static struct option long_options[] = {
		{"ip",		required_argument,	0,  0 },
		{"port",	required_argument,	0,  1 },
		{"proto",	required_argument,	0,  2 },
		{"msg",		required_argument,	0,  3 },
		{0,			0,					0,  0 }
	};

	while ((opt = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1) {
		switch (opt) {
		case 0: // --ip
			if (inet_pton(AF_INET, optarg, &ip) != 1) {
				fprintf(stderr, "Invalid source IP: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 1: // --port
			port = (uint16_t)strtoul(optarg, NULL, 10);
			if (!validate_port(port)) {
				fprintf(stderr, "Invalid destination port: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;	

		case 2: // --proto
			proto = validate_proto(optarg);
			if (!proto) {
				fprintf(stderr, "Unsupported protocol: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
			
		case 3: // --msg
			strcpy(msg, optarg);
			break;
			
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	// Запускаем клиента
	if (proto == IPPROTO_TCP) 
		tcp_client(ip, port, msg);
	else
		udp_client(ip, port, msg);

	return 0;
}

/*
 * tcp-echo-client.c
 */

int tcp_client(struct in_addr ip, int port, char *msg)
{
	int sockfd, n;
	struct sockaddr_in servaddr;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) 
		die("socket()");

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = ip.s_addr;
	servaddr.sin_port = htons(port);

	if (connect(sockfd, (SA*)&servaddr, (socklen_t)sizeof(servaddr)) != 0)
	{
		close(sockfd);
		die("connect()");
	}

	write(sockfd, msg, strlen(msg));
	memset(msg, 0, BUF_SIZE);

	n = read(sockfd, msg, sizeof(msg));

	if (n < 0)
	{
		close(sockfd);
		die("read()");
	}
	
	printf("From server : %s\n", msg);

	close(sockfd);
	return 0;
}

int udp_client(struct in_addr ip, int port, char *msg)
{
	int sockfd, n; 
	struct sockaddr_in servaddr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if (sockfd < 0)
		die("socket()");

	memset(&servaddr, 0, sizeof(servaddr)); 
	servaddr.sin_addr.s_addr = ip.s_addr; 
	servaddr.sin_port = htons(port); 
	servaddr.sin_family = AF_INET;

	if(connect(sockfd, (struct sockaddr *)&servaddr, (socklen_t)sizeof(servaddr)) < 0) 
		die("connect()");

	n = send(sockfd, msg, strlen(msg), 0);
	if (n < 0)
		die("send()");

	memset(msg, 0, BUF_SIZE);

	n = read(sockfd, msg, BUF_SIZE);
	if (n < 0)
	{
		close(sockfd);
		die("recv()");
	}

	printf("From server : %s\n", msg);

	close(sockfd);
	return 0;
}

// Валидация порта
static int validate_port(uint16_t port) 
{
	return port > 0 && port <= 65535;
}

// Валидация протокола
static int validate_proto(const char *proto) 
{
	if (strcasecmp(proto, "tcp") == 0) return IPPROTO_TCP;
	if (strcasecmp(proto, "udp") == 0) return IPPROTO_UDP;
	return 0;
}

void print_usage(char *app_name) 
{
	printf("Usage: %s [OPTIONS]\n"
		   "Options:\n"
		   "\t--ip IP\tSource IP address\n"
		   "\t--port PORT\tDestination port\n"
		   "\t--proto PROTO\tTransport protocol (tcp/udp)\n"
		   "\t--msg PORT\tMessage to echo\n", app_name);
}