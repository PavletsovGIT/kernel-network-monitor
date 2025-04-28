#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "/home/pavletsov21/eltex/knm/common/ioctl_cmd.h"

#define DEVICE_NAME "/dev/mynetmod"

// Прототипы функций валидации
static int validate_port(uint16_t port);
static int validate_proto(const char *proto);

void print_usage();

int main(int argc, char *argv[]) {
	struct app_cmd config;
	struct kern_cmd kern_config;
	int opt;
	int option_index = 0;
	int dev;
	char buf[BUF_SIZE] = {0};

	// Инициализация дескриптора файла драйвера
	dev = open(DEVICE_NAME, O_WRONLY);
	if (dev == -1) {
		perror("open");
		return -1;
	}

	// Инициализация config'ов
	memset(&config, 0, sizeof(config));
	memset(&kern_config, 0, sizeof(kern_config));
	
	static struct option long_options[] = {
		{"ipsrc",      required_argument, 0,  0 },
		{"ipdst",      required_argument, 0,  1 },
		{"transport",  required_argument, 0,  2 },
		{"portsrc",    required_argument, 0,  3 },
		{"portdst",    required_argument, 0,  4 },
		{"show",       no_argument,       0,  5 },
		{"filter",     required_argument, 0,  6 },
		{0,            0,                 0,  0 }
	};

	while ((opt = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1) {
		switch (opt) {
		case 0: // --ipsrc
			if (inet_pton(AF_INET, optarg, &config.rule.src_ip) != 1) {
				fprintf(stderr, "Invalid source IP: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.rule.defined_fields |= SRC_IP_BIT_MASK;
			break;
			
		case 1: // --ipdst
			if (inet_pton(AF_INET, optarg, &config.rule.dst_ip) != 1) {
				fprintf(stderr, "Invalid destination IP: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.rule.defined_fields |= DST_IP_BIT_MASK;
			break;
			
		case 2: // --transport
			config.rule.proto = validate_proto(optarg);
			if (!config.rule.proto) {
				fprintf(stderr, "Unsupported protocol: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.rule.defined_fields |= PROTO_BIT_MASK;
			break;
			
		case 3: // --portsrc
			config.rule.src_port = htons((uint16_t)strtoul(optarg, NULL, 10));
			if (!validate_port(config.rule.src_port)) {
				fprintf(stderr, "Invalid source port: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.rule.defined_fields |= SRC_PORT_BIT_MASK;
			break;
			
		case 4: // --portdst
			config.rule.dst_port = htons((uint16_t)strtoul(optarg, NULL, 10));
			if (!validate_port(config.rule.dst_port)) {
				fprintf(stderr, "Invalid destination port: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.rule.defined_fields |= DST_PORT_BIT_MASK;
			break;
			
		case 5: // --show
			config.command = CMD_SHOW_STATS;
			break;
			
		case 6: // --filter
			if (strcmp(optarg, "enable") == 0) {
				config.command = CMD_ADD_RULE;
			} else if (strcmp(optarg, "disable") == 0) {
				config.command = CMD_DEL_RULE;
			} else {
				fprintf(stderr, "Invalid filter action: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
			
		default:
			print_usage();
			exit(EXIT_FAILURE);
		}
	}

	// Валидация комбинаций параметров
	if (!(config.command == CMD_ADD_RULE || config.command == CMD_DEL_RULE) && !(config.rule.defined_fields != 0)) 
	{
		fprintf(stderr, "Rule must have at least one criteria\n");
		exit(EXIT_FAILURE);
	}

	printf("Formed rule | ipsrc : %d | ipdst : %d | portsrc : %d | portdst : %d | proto : %s | def_f : %d\n", config.rule.src_ip.s_addr, 
					config.rule.dst_ip.s_addr, config.rule.src_port, 
					config.rule.dst_port, (config.rule.proto == IPPROTO_TCP) ? "tcp" : "udp",config.rule.defined_fields);

	// Копируем данные из config в kern_config для передачи в ядро
	kern_config.rule = config.rule;
	// Передача команды в ядро (только kern_rule или ссылку на buf, если это show)
	switch (config.command)
	{
		case CMD_NONE:
			break;
		case CMD_ADD_RULE:
			// Добавляет правило
			ioctl(dev, ADD_RULE, &kern_config);
			break;
		case CMD_DEL_RULE:
			// удаляет правило
			ioctl(dev, DEL_RULE, &kern_config);
			break;
		case CMD_SHOW_STATS:
			// считывает статистику
			ioctl(dev, SHOW, buf);
			break;
		default:
			break;
	}

	// Обработка результата
	if (kern_config.res < 0)
	{
		fprintf(stderr, "ERROR");
	}

	return 0;
}

// Валидация порта
static int validate_port(uint16_t port) {
	return port > 0 && port <= 65535;
}

// Валидация протокола
static int validate_proto(const char *proto) {
	if (strcasecmp(proto, "tcp") == 0) return IPPROTO_TCP;
	if (strcasecmp(proto, "udp") == 0) return IPPROTO_UDP;
	return 0;
}

void print_usage() {
	printf("Usage: %s [OPTIONS]\n"
		   "Options:\n"
		   "  --ipsrc IP         Source IP address\n"
		   "  --ipdst IP         Destination IP address\n"
		   "  --transport PROTO  Transport protocol (tcp/udp)\n"
		   "  --portsrc PORT     Source port\n"
		   "  --portdst PORT     Destination port\n"
		   "  --show             Show statistics\n"
		   "  --filter ACTION    Enable/disable filter (enable|disable)\n");
}