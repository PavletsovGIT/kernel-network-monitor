#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define COMMANDS_NUM	4
#define BUF_SIZE		64
#define LISTEN_NUM		5
#define SA 				struct sockaddr

static void die(const char *s) { perror(s); exit(1); }

int tcp_server(int port);
int udp_server(int port);

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
	int opt;
	int option_index = 0;

	// Структура принимаемых команд
	static struct option long_options[] = {
		{"port",	required_argument,	0,  0 },
		{"proto",	required_argument,	0,  1 },
		{0,			0,					0,  0 }
	};

	while ((opt = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1) {
		switch (opt) {

		case 0: // --port
			port = (uint16_t)strtoul(optarg, NULL, 10);
			if (!validate_port(port)) {
				fprintf(stderr, "Invalid destination port: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 1: // --proto
			proto = validate_proto(optarg);
			if (!proto) {
				fprintf(stderr, "Unsupported protocol: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
			
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("Start server\n");

	// Запускаем клиента
	if (proto == IPPROTO_TCP) tcp_server(port);
	if (proto == IPPROTO_UDP) udp_server(port);
}

int tcp_server(int port)
{
	int sockfd, connfd, n;
	struct sockaddr_in servaddr, cli; 
	char buf[BUF_SIZE] = {0};
	socklen_t len;

	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) 
		die("socket()");

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(port); 

	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) < 0) 
	{
		close(sockfd);
		die("bind()");
	}

	if ((listen(sockfd, LISTEN_NUM)) < 0) 
	{
		close(sockfd);
		die("listen()");
	}

	len = sizeof(cli);
	
	while (1)
	{
		connfd = accept(sockfd, (SA *)&cli, &len);
		if (connfd < 0)
		{
			perror("accept()");
			continue;
		}

		n = read(connfd, buf, BUF_SIZE);
		printf("Received %d bytes.\n", n);

		write(connfd, buf, n);
		close(connfd);
		memset(buf, 0, BUF_SIZE);
	}

	close(sockfd);
	return 1;
}

int udp_server(int port)
{
	int sockfd, n;
	char buf[BUF_SIZE] = {0};
	struct sockaddr_in servaddr, cliaddr;
	socklen_t len;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		die("socket()");

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(port); 
	
	if (bind(sockfd, (SA *)&servaddr, sizeof(servaddr)) < 0)
	{
		close(sockfd);
		die("bind()");
	}

	len = sizeof(servaddr);

	while (1)
	{
		n = recvfrom(sockfd, buf, sizeof(buf), 0, (SA *)&cliaddr, &len);
		if (n < 0)
		{
			close(sockfd);
			die("recvfrom()");
		}
		printf("Received %d bytes.\n", n);

		n = sendto(sockfd, buf, sizeof(buf), 0, (SA *)&cliaddr, (socklen_t)sizeof(cliaddr));
		if (n < 0)
		{
			close(sockfd);
			die("recvfrom()");
		}

		memset(&cliaddr, 0, sizeof(cliaddr));
		memset(buf, 0, BUF_SIZE);
	}

	close(sockfd);
	return 1;
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
		   "\t--port PORT\tDestination port\n"
		   "\t--proto PROTO\tTransport protocol (tcp/udp)\n", app_name);
}