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

static struct nf_hook_ops *nf_tracer_ops = NULL;
static struct nf_hook_ops *nf_tracer_out_ops = NULL;

#include "/home/pavletsov21/eltex/knm/common/ioctl_cmd.h"

#define SRC_IP_BIT_NUM 		0		// 00000001
#define DST_IP_BIT_NUM 		1		// 00000010
#define SRC_PORT_BIT_NUM 	2		// 00000100
#define DST_PORT_BIT_NUM 	3		// 00001000
#define PROTO_BIT_NUM 		4		// 00010000

#define SRC_IP_BIT_MASK 	0x1		// 00000001
#define DST_IP_BIT_MASK 	0x2		// 00000010
#define SRC_PORT_BIT_MASK 	0x4		// 00000100
#define DST_PORT_BIT_MASK 	0x8		// 00001000
#define PROTO_BIT_MASK 		0x10	// 00010000

#define MAX_RULES 10

static struct kern_rule rules_list[MAX_RULES];
static uint8_t rules_count;

static uint8_t add_rule(struct kern_rule *rule)
{
	/* Проверка на заполненность списка правил */
	if (rules_count == MAX_RULES)
		return -1;

	memcpy(&rules_list[rules_count], rule, sizeof(struct kern_rule));
	rules_count++;

	return 1;
}

/* Алгоритм работы:
 * 1. Выбираем правило
 * 2. Смотрим, если бит n-ого параметра равен 1, то:
 * 2.1 Сравниваем n-ый параметр с соответствующим параметром структуры
 * 2.2 Если совпали, то
 * 2.2.1 Выставляем соответствующий бит в переменной res в 1
 * 3. Если res равен "битовой маске" (defined_rules), то блокируем пакет, иначе не блокируемы 
 */
static uint8_t is_need_to_drop(struct iphdr *orig_iph, struct tcphdr *orig_tcph, struct udphdr *orig_udph)
{
	int i;
	uint8_t res = 0;

	for (i = 0; i < rules_count; i++)
	{
		pr_info("src ip test : %d, src ip pack : %d", rules_list[i].src_ip.s_addr, orig_iph->saddr);
		pr_info("dst ip test : %d, dst ip pack : %d", rules_list[i].dst_ip.s_addr, orig_iph->daddr);
		pr_info("proto test : %s, proto pack : %s", (rules_list[i].proto == IPPROTO_TCP) ? "tcp" : "udp", (orig_iph->protocol) == IPPROTO_TCP ? "tcp" : "udp");
		pr_info("src port test : %d, src port pack : %d", rules_list[i].src_port, orig_tcph->source);
		pr_info("dst port test : %d, dst port pack : %d", rules_list[i].src_port, orig_tcph->source);
		if (rules_list[i].defined_fields & SRC_IP_BIT_MASK)
		{
			if (rules_list[i].src_ip.s_addr == orig_iph->saddr)
				res |= SRC_IP_BIT_MASK;
		}

		if (rules_list[i].defined_fields & DST_IP_BIT_MASK)
		{
			if (rules_list[i].dst_ip.s_addr == orig_iph->daddr)
				res |= DST_IP_BIT_MASK;
		}

		if (rules_list[i].defined_fields & PROTO_BIT_MASK)
		{
			if (rules_list[i].proto == orig_iph->protocol)
				res |= PROTO_BIT_MASK;
		}

		if (rules_list[i].defined_fields & SRC_PORT_BIT_MASK)
		{
			if (orig_tcph == NULL) // Проверяем udp
			{
				if (rules_list[i].src_port == orig_udph->source)
					res |= SRC_PORT_BIT_MASK;
			} else 
			{
				if (rules_list[i].src_port == orig_tcph->source)
					res |= SRC_PORT_BIT_MASK;
			}
		}

		if (rules_list[i].defined_fields & DST_PORT_BIT_MASK)
		{
			if (orig_tcph == NULL) // Проверяем udp
			{
				if (rules_list[i].dst_port == orig_udph->dest)
					res |= DST_PORT_BIT_MASK;
			} else 
			{
				if (rules_list[i].dst_port == orig_tcph->dest)
					res |= DST_PORT_BIT_MASK;
			}
		}

		if (res == rules_list[i].defined_fields)
			return 1;
	}

	return 0;
}

static uint8_t sada_is_need_to_drop(struct iphdr *orig_iph, struct tcphdr *orig_tcph, struct udphdr *orig_udph)
{
	/* Переделать на побитовый сдвиг результата XOR, вместо if */
	uint8_t res = 0;
	int i;

	for (i = 0; i < rules_count; i++)
	{
		pr_info("src ip test : %d, src ip pack : %d", rules_list[i].src_ip.s_addr, orig_iph->saddr);
		if (rules_list[i].src_ip.s_addr == orig_iph->saddr)
		{
			res |= SRC_IP_BIT_MASK;
		}
		pr_info("dst ip test : %d, dst ip pack : %d", rules_list[i].dst_ip.s_addr, orig_iph->daddr);
		if (rules_list[i].dst_ip.s_addr == orig_iph->daddr)
			res |= DST_IP_BIT_MASK;

		if (orig_iph->protocol == IPPROTO_TCP)
		{
			res |= PROTO_BIT_MASK;

			pr_info("src port test : %d, src port pack : %d", rules_list[i].src_port, orig_tcph->source);
			if (rules_list[i].src_port == orig_tcph->source)
				res |= SRC_PORT_BIT_MASK;

			pr_info("dst port test : %d, dst port pack : %d", rules_list[i].src_port, orig_tcph->source);
			if (rules_list[i].dst_port == orig_tcph->dest)
				res |= DST_PORT_BIT_MASK;
		} else 
		{ /* orig_iph->protocol == IPPROTO_UDP */
			res |= PROTO_BIT_MASK;

			if (rules_list[i].src_port == orig_udph->source)
				res |= SRC_PORT_BIT_MASK;

			if (rules_list[i].dst_port == orig_udph->dest)
				res |= DST_PORT_BIT_MASK;
		}

		if (!(rules_list[i].defined_fields & res))
			return 1;

		res = 0;
	}



	return 0;
}

static unsigned int nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) 
{	
	if(skb==NULL) {
		return NF_ACCEPT;
	}

	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	struct iphdr * iph;
	iph = ip_hdr(skb);

	// Вывод TCP пакетов
	if(iph && iph->protocol == IPPROTO_TCP) 
	{
		tcph = tcp_hdr(skb);
		pr_info("proto : tcp | source : %pI4:%hu | dest : %pI4:%hu | seq : %u | ack_seq : %u | window : %hu | csum : 0x%hx | urg_ptr %hu\n", &(iph->saddr),ntohs(tcph->source),&(iph->daddr),ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window), ntohs(tcph->check), ntohs(tcph->urg_ptr));
	}

	// Вывод UDP дейтаграмм
	if (iph && iph->protocol == IPPROTO_UDP) 
	{
		// Считываем из буфера как upd дейтаграммму
		udph = udp_hdr(skb);
		pr_info("proto : udp | source : %pI4:%hu | dest : %pI4:%hu | length : %u | check : %u\n", &(iph->saddr), ntohs(udph->source), &(iph->daddr), ntohs(udph->dest), ntohs(udph->len), ntohl(udph->check));
	}

	// Смотрим подходит ли пакет по шаблонну
	if (iph->protocol == IPPROTO_TCP)
	{
		if (is_need_to_drop(iph, tcph, NULL))
		{
			pr_info("Packet has been dropped\n");
			return NF_DROP;
		}
	}

	if (iph->protocol == IPPROTO_UDP)
	{
		if (is_need_to_drop(iph, NULL, udph))
		{
			pr_info("Packet has been dropped\n");
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}


static int __init nf_tracer_init(void) 
{
	// Как то решить вопрос с инициализацей 255.

	/* Инициализация rules_list */
	memset(rules_list, 0, MAX_RULES * sizeof(struct kern_rule));
	rules_count = 0;

	/* Тестовое правило для блокировки udp трафика с udp-сервера */
	rules_list[0].src_ip.s_addr = 16777343; // 127.0.0.1
	rules_list[0].src_port = 8080;
	rules_list[0].proto = IPPROTO_UDP;
	rules_list[0].defined_fields = SRC_IP_BIT_MASK | SRC_PORT_BIT_MASK | PROTO_BIT_MASK;
	rules_count++;

	nf_tracer_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);

	if(nf_tracer_ops!=NULL) {
		nf_tracer_ops->hook = (nf_hookfn*)nf_tracer_handler;
		nf_tracer_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_tracer_ops->pf = NFPROTO_IPV4;
		nf_tracer_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_tracer_ops);
	}

	nf_tracer_out_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	if(nf_tracer_out_ops != NULL) {
		nf_tracer_out_ops->hook = (nf_hookfn*)nf_tracer_handler;
		nf_tracer_out_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_tracer_out_ops->pf = NFPROTO_IPV4;
		nf_tracer_out_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_tracer_out_ops);
	}

	return 0;
}

static void __exit nf_tracer_exit(void) {

	if(nf_tracer_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_tracer_ops);
		kfree(nf_tracer_ops);
	}

	if(nf_tracer_out_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_tracer_out_ops);
		kfree(nf_tracer_out_ops);
	}
}

module_init(nf_tracer_init);
module_exit(nf_tracer_exit);

MODULE_LICENSE("GPL");