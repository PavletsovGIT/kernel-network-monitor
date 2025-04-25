#ifndef IOCTL_CMD_H_
#define IOCTL_CMD_H_

#define NAME_SIZE 64

#define BUF_SIZE 1024

#define SRC_IP_BIT_MASK 	0x1		// 00000001
#define DST_IP_BIT_MASK 	0x2		// 00000010
#define SRC_PORT_BIT_MASK 	0x4		// 00000100
#define DST_PORT_BIT_MASK 	0x8		// 00001000
#define PROTO_BIT_MASK 		0x10	// 00010000

/* defined_fields - переменная для указания какие поля в kern_rule заполнены
 * 0 бит - src_ip
 * 1 бит - dst_ip
 * 2 бит - src_port
 * 3 бит - dst_port
 * 4 бит - proto
 * 5 бит - Резерв
 * 6 бит - Резерв
 * 7 бит - Резерв
 */
struct kern_rule {
	struct in_addr src_ip;
	struct in_addr dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t defined_fields;
};

// Структура для хранения параметров
struct app_cmd {
	struct kern_rule rule;
	enum { 
		CMD_NONE,
		CMD_ADD_RULE,
		CMD_DEL_RULE,
		CMD_SHOW_STATS
	} command;
};

struct kern_cmd {
	struct kern_rule rule;
	uint8_t res;
};

// Добавление правила в фильтр
#define ADD_RULE _IOW('a', 'a', struct kern_cmd *)
// Удаление правила из фильтра
#define DEL_RULE _IOR('a', 'b', struct kern_cmd *)
// Чтение стсатистики из ядра
#define SHOW _IOR('a', 'c', char *)

#endif // IOCTL_CMD_H_