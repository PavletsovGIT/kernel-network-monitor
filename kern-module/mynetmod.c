#include "./mynetmod.h"

static struct kern_rule rules_list[MAX_RULES];
static uint8_t rules_count;

/* Настравиваем работу с модулем */
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = device_open,
	.release = device_exit, 
	.unlocked_ioctl = ioctl_handler
};

/* Инициализация списка правил */
static uint8_t init_rules_list()
{
	memset(rules_list, 0, MAX_RULES * sizeof(struct kern_rule));
	rules_count = 0;

	return 1;
}

/* Для добавления правила */
static uint8_t add_rule(struct kern_rule *rule)
{
	if (rules_count == MAX_RULES) return EFULLRL;

	memcpy(rules_list[rules_count], rule, sizeof(struct kern_rule));

	return 1;
}

/* Для удаления правила */
static uint8_t remove_rule(struct kern_rule *rule)
{
	return -1;
}

/* Сверяет пакет с правилами в фильтре. Возвр 1 если пакет идентичен одному из правил
 * и возвр. 0, если совпадений не найдено.
 * Если используется для TCP, то orig_udph == NULL
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
			if (orig_tcph == NULL) /* Проверяем udp */
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
			if (orig_tcph == NULL) /* Проверяем udp */
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

/* Обработчик хука IP_PRE_ROUTING */
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

/* Обработчик команд ioctl */
static long int ioctl_handler(struct file *file, unsigned cmd, unsigned long arg)
{
	/* Структура для записи команд от пользователя и ответа */
	struct kern_cmd user_cmd;

	switch (cmd)
	{
		case ADD_RULE:
			break;

		case DEL_RULE:
			break;

		default:
			break;
	}
}

/* Функция, вызываемая при открытии файла /dev/mynetmod */
static int device_open(struct inode *device_file, struct file *instance)
{
	pr_info("mynetmod : Open device file\n");
	return 0;
}

/* Функция, вызываемая при закрытии файла /dev/mynetmod */
static int device_exit(struct inode *device_file, struct file *instance)
{
	pr_info("mynetmod : Close device file\n");
	return 0;
}

/* Функция инициализации модуля ядра */
static int __init mynetmod_init(void)
{
	/* Инициализация rules_list */
	init_rules_list();

	/* alloc memory for hook */
	nf_tracer_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	nf_tracer_out_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	/* register hooks */
	if (nf_tracer_ops!=NULL) 
	{
		nf_tracer_ops->hook = (nf_hookfn*)nf_tracer_handler;
		nf_tracer_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_tracer_ops->pf = NFPROTO_IPV4;
		nf_tracer_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_tracer_ops);
	}	

	if (nf_tracer_out_ops != NULL) 
	{
		nf_tracer_out_ops->hook = (nf_hookfn*)nf_tracer_handler;
		nf_tracer_out_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_tracer_out_ops->pf = NFPROTO_IPV4;
		nf_tracer_out_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_tracer_out_ops);
	}

	return 0;
}

/* Функция деструктор модуля ядра */
static void __exit mynetmod_exit(void)
{
	/* ... */
	if(nf_tracer_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_tracer_ops);
		kfree(nf_tracer_ops);
	}

	if(nf_tracer_out_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_tracer_out_ops);
		kfree(nf_tracer_out_ops);
	}
}

module_init(mynetmod_init);
module_exit(mynetmod_exit);

MODULE_AUTHOR("Pavletsov Feodor, tg: @ebashiox");
MODULE_LICENSE("GPL");