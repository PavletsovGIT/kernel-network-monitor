#ifndef MYNETMOG_H_
#define MYNETMOD_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>

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
	uint32_t blocking_count; 
};

struct kern_cmd {
	struct kern_rule rule;
	uint8_t res;
};

// Добавление правила в фильтр
#define ADD_RULE _IOWR('a', 'a', struct kern_cmd *)
// Удаление правила из фильтра
#define DEL_RULE _IOWR('a', 'b', struct kern_cmd *)
// Чтение стсатистики из ядра
//#define SHOW _IOR('a', 'c', char *)

#define DEVICE_NAME "mynetmod"
#define PROC_STATS_NAME "bl_stats"

static struct nf_hook_ops *nf_tracer_ops = NULL;
static struct nf_hook_ops *nf_tracer_out_ops = NULL;

/* Список ошибок */
enum {
	EFULLRL = -1,					/* Error FULL Rull List - Список правил заполнен */
	EREMRULE						/* Error REMoving RULE - Список правил заполнен */
} mynetmod_errors;

#define SRC_IP_BIT_NUM 		0
#define DST_IP_BIT_NUM 		1
#define SRC_PORT_BIT_NUM 	2
#define DST_PORT_BIT_NUM 	3
#define PROTO_BIT_NUM 		4

#define SRC_IP_BIT_MASK 	0x1		/* 00000001 */
#define DST_IP_BIT_MASK 	0x2		/* 00000010 */
#define SRC_PORT_BIT_MASK 	0x4		/* 00000100 */
#define DST_PORT_BIT_MASK 	0x8		/* 00001000 */
#define PROTO_BIT_MASK 		0x10	/* 00010000 */

#define MAX_RULES	10
#define BUF_SIZE	1024

/* Запись прафила в строку */
static uint8_t print_rule(struct kern_rule *rule, char *buf, size_t buf_length);

/* Запись пакета в строку */
static uint8_t print_packet(struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, char *buf, size_t buf_length);

/* Проверка пакета и правила на идентичность данных */
static uint8_t is_packet_equal_rule(struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct kern_rule *rule);

/* Инициализация списка правил */
static uint8_t init_rules_list(void);

/* Для добавления правила */
static uint8_t add_rule(struct kern_rule *rule);

/* Для удаления правила */
static uint8_t remove_rule(struct kern_rule *rule);

/* Сверяет пакет с правилами в фильтре. Возвр 1 если пакет идентичен одному из правил
 * и возвр. 0, если совпадений не найдено.
 * Если используется для TCP, то orig_udph == NULL
 */
static uint8_t is_need_to_drop(struct iphdr *orig_iph, struct tcphdr *orig_tcph, struct udphdr *orig_udph);

/* Обработчик хука IP_PRE_ROUTING */
static unsigned int nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/* Обработчик команд ioctl */
static long int ioctl_handler(struct file *file, unsigned cmd, unsigned long arg);

/* Функция, вызываемая при открытии файла /dev/mynetmod */
static int device_open(struct inode *device_file, struct file *instance);

/* Функция, вызываемая при закрытии файла /dev/mynetmod */
static int device_exit(struct inode *device_file, struct file *instance);

/* Функция для записи статиситки в переменную buf */
static void get_stats(char *buf, size_t buf_length);

/* Функция для чтения файла /proc */
static ssize_t mynetmod_read(struct file *File, char __user *user_buf, size_t count, loff_t *offs);

/* Функция инициализации модуля ядра */
static int __init mynetmod_init(void);

/* Функция деструктор модуля ядра */
static void __exit mynetmod_exit(void);

#endif // MYNETMOD_H_