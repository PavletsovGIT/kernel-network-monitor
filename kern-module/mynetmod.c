#include "./mynetmod.h"

static int major;
static int minor;

static struct class *cls;

/* Переменные для директории и файла в procfs */
static struct proc_dir_entry *proc_folder;
static struct proc_dir_entry *proc_file;

static struct kern_rule rules_list[MAX_RULES];
static uint8_t rules_count;

/* Настравиваем работу с модулем через /dev */
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = device_open,
	.release = device_exit, 
	.unlocked_ioctl = ioctl_handler
};

/* Настравиваем работу с можулем через /proc */
static struct proc_ops pops = {
	.proc_read = mynetmod_read
};


static uint8_t print_rule(struct kern_rule *rule, char *buf, size_t buf_length)
{
	return snprintf(buf, buf_length, "Rule | ipsrc : %pI4:%hu | ipdst : %pI4:%hu | proto : %s | def_f : %d\n", &rule->src_ip, rule->src_port, 
										&rule->dst_ip, rule->dst_port, 
										(rule->proto == IPPROTO_TCP) ? "TCP" : "UDP", rule->defined_fields);
}

static uint8_t print_packet(struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, char *buf, size_t buf_length)
{
	uint16_t source_port, dest_port, proto;
	if (udph == NULL)
	{
		proto = IPPROTO_TCP;
		source_port = tcph->source;
		dest_port = tcph->dest;
	} else
	{
		proto = IPPROTO_UDP;
		source_port = udph->source;
		dest_port = udph->dest;
	}

	return snprintf(buf, buf_length, "Packet | ipsrc : %pI4:%hu | ipdst : %pI4:%hu | proto : %s\n", &iph->saddr, source_port, 
										&iph->daddr, dest_port, (proto == IPPROTO_TCP) ? "TCP" : "UDP");
}

static uint8_t is_packet_equal_rule(struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct kern_rule *rule)
{
	if (rule->defined_fields == 0) return 0; // Игнорируем пустые правила
	
	//uint16_t matched = 0;
	
	if ((rule->defined_fields & SRC_IP_BIT_MASK) && 
		(rule->src_ip.s_addr != iph->saddr)) return 0;
	
	if ((rule->defined_fields & DST_IP_BIT_MASK) && 
		(rule->dst_ip.s_addr != iph->daddr)) return 0;
	
	if ((rule->defined_fields & PROTO_BIT_MASK) && 
		(rule->proto != iph->protocol)) return 0;
	
	if (rule->defined_fields & SRC_PORT_BIT_MASK) {
		uint16_t packet_port = (tcph) ? tcph->source : udph->source;
		if (rule->src_port != packet_port) return 0;
	}
	
	if (rule->defined_fields & DST_PORT_BIT_MASK) {
		uint16_t packet_port = (tcph) ? tcph->dest : udph->dest;
		if (rule->dst_port != packet_port) return 0;
	}
	
	return 1;
}

/* Сравнивает 2 правила.
 * Возвращает 0, если правила разные и 1 в ином случае.
 */
static uint8_t kern_rule_cmp(struct kern_rule *rule_a, struct kern_rule *rule_b)
{
	if (rule_a->defined_fields != rule_b->defined_fields) return 0;

	if ((rule_a->src_ip.s_addr != rule_b->src_ip.s_addr) || \
		(rule_a->dst_ip.s_addr != rule_b->dst_ip.s_addr) || \
		(rule_a->src_port != rule_b->src_port) || \
		(rule_a->dst_port != rule_b->dst_port) || \
		(rule_a->proto != rule_b->proto))
		return 0;

	return 1;
}

/* Копирует поля одного правила в другое */
static uint8_t kern_rule_cpy(struct kern_rule *dst, struct kern_rule *src)
{
	dst->src_ip.s_addr = src->src_ip.s_addr;
	dst->dst_ip.s_addr = src->dst_ip.s_addr;
	dst->src_port = src->src_port;
	dst->dst_port = src->dst_port;
	dst->proto = src->proto;
	dst->defined_fields = src->defined_fields;

	return 1;
}

/* Заполняет все поля правила нулями */
static uint8_t ker_rule_init(struct kern_rule *rule)
{
	rule->src_ip.s_addr = 0;
	rule->dst_ip.s_addr = 0;
	rule->src_port = 0;
	rule->dst_port = 0;
	rule->proto = 0;
	rule->defined_fields = 0;

	return 1;
}

/* Инициализация списка правил */
static uint8_t init_rules_list(void)
{
	for (int i = 0; i < MAX_RULES; i++)
		ker_rule_init(&rules_list[i]);
	rules_count = 0;

	return 1;
}

/* Для добавления правила */
static uint8_t add_rule(struct kern_rule *rule)
{
	/* Вдруг заполнено */
	if (rules_count == MAX_RULES) return EFULLRL;

	/* Присваиваем последнему элементу */
	//memcpy(&rules_list[rules_count], rule, sizeof(struct kern_rule));
	rules_list[rules_count] = *rule; 
	rules_count++;

	return 1;
}

/* Для удаления правила */
static uint8_t remove_rule(struct kern_rule *rule)
{
	int i, j;
	for (i = 0; i < rules_count; i++)
	{
		if (kern_rule_cmp(&rules_list[i], rule) == 0)
			continue;
			
		/* Удаляем данное правило */
		ker_rule_init(&rules_list[i]);

		/* Сдвигаем все след правила влево */
		for (j = i; j < rules_count - 1; j++)
		{
			kern_rule_cpy(&rules_list[j], &rules_list[j + 1]);
		}

		/* Затираем последний элемент */
		ker_rule_init(&rules_list[rules_count - 1]);

		/* Уменьшаем счетчик */
		rules_count--;
		return 1;
	}

	return -1;
}

/* Сверяет пакет с правилами в фильтре. Возвр 1 если пакет идентичен одному из правил
 * и возвр. 0, если совпадений не найдено.
 * Если используется для TCP, то orig_udph == NULL
 */
static uint8_t is_need_to_drop(struct iphdr *orig_iph, struct tcphdr *orig_tcph, struct udphdr *orig_udph)
{
	int i;
	for (i = 0; i < rules_count; i++)
	{
		if (orig_tcph == NULL)
		{
			if (is_packet_equal_rule(orig_iph, NULL, orig_udph, &rules_list[i]))
				return 1;
		} else 
		{
			if (is_packet_equal_rule(orig_iph, orig_tcph, NULL, &rules_list[i]))
				return 1;
		}
	}

	return 0;
}

/* Обработчик хука IP_PRE_ROUTING */
static unsigned int nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{	
	if (skb==NULL) {
		return NF_ACCEPT;
	}

	char buf[BUF_SIZE] = {0};

	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	struct iphdr * iph;
	iph = ip_hdr(skb);

	// Вывод TCP пакетов
	if(iph && iph->protocol == IPPROTO_TCP) 
	{
		/* Считываем пакет как tcp-сегмент */
		tcph = tcp_hdr(skb);
		/* Печатаем данные */
		print_packet(iph, tcph, NULL, buf, BUF_SIZE);
		pr_info("%s", buf);
	}

	/* Вывод UDP дейтаграмм */
	if (iph && iph->protocol == IPPROTO_UDP) 
	{
		/* Считываем из буфера как upd-дейтаграммму */
		udph = udp_hdr(skb);
		/* Печатаем данные */
		print_packet(iph, NULL, udph, buf, BUF_SIZE);
		pr_info("%s", buf);
	}

	/* Смотрим нужно ли отбросить пакет */
	if (iph->protocol == IPPROTO_TCP)
	{
		if (is_need_to_drop(iph, tcph, NULL))
		{
			pr_info("Packet has been dropped\n");
			return NF_DROP; /* Отбрасываем пакет */
		}
	}

	/* Смотрим нужно ли отбросить пакет */
	if (iph->protocol == IPPROTO_UDP)
	{
		if (is_need_to_drop(iph, NULL, udph))
		{
			pr_info("Packet has been dropped\n");
			return NF_DROP; /* Отбрасываем пакет */
		}
	}

	return NF_ACCEPT;
}

/* Обработчик команд ioctl */
static long int ioctl_handler(struct file *file, unsigned cmd, unsigned long arg)
{
	/* Структура для записи команд от пользователя и ответа */
	struct kern_cmd user_cmd;
	int res;
	char buf[BUF_SIZE] = {0};

	/* Инициализация */
	ker_rule_init(&user_cmd.rule);
	user_cmd.res = 0;

	switch (cmd)
	{
		case ADD_RULE:
			/* Читаем команду с правилом от пользователя */
			if (copy_from_user(&user_cmd, (struct kern_cmd *)arg, sizeof(user_cmd)))
			{
				pr_err("mynetmod : Error copying data from user\n");
				break;
			}

			/* Добавляем правило и печатаем назад результат */
			res = add_rule(&user_cmd.rule);
			/* Возвращаем с результатом добавления */
			user_cmd.res = res;
			if (copy_to_user((struct kern_cmd *)arg, &user_cmd, sizeof(user_cmd)))
			{
				pr_err("mynetmod : Error copying data to user\n");
				break;
			}

			print_rule(&user_cmd.rule, buf, BUF_SIZE);
			pr_info("Added %s\n", buf);
			break;

		case DEL_RULE:
			/* Читаем команду с правилом от пользователя */
			if (copy_from_user(&user_cmd, (struct kern_cmd *)arg, sizeof(user_cmd)))
			{
				pr_err("mynetmod : Error copying data from user\n");
				break;
			}

			/* Добавляем правило и печатаем назад результат */
			res = remove_rule(&user_cmd.rule);
			/* Возвращаем с результатом добавления */
			user_cmd.res = res;
			if (copy_to_user((struct kern_cmd *)arg, &user_cmd, sizeof(user_cmd)))
			{
				pr_err("mynetmod : Error copying data to user\n");
				break;
			}

			print_rule(&user_cmd.rule, buf, BUF_SIZE);
			pr_info("Removed %s\n", buf);
			break;

		default:
			break;
	}

	return 0;
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

/* Функция для записи статиситки в переменную buf */
static void get_stats(char *buf, size_t buf_length)
{
	int offs, i;
	offs = snprintf(buf, buf_length, "There are rules : %d\n", rules_count);

	for (i = 0; i < rules_count; i++)
	{
		offs += snprintf(buf + offs, buf_length - offs, "i : %d | src ip : %d | dst ip : %d | src port : %d | dst prt : %d | proto : %s | def_f : %d\n", \
				i + 1, rules_list[i].src_ip.s_addr, rules_list[i].dst_ip.s_addr, rules_list[i].src_port, rules_list[i].dst_port, \
				(rules_list[i].proto == IPPROTO_TCP) ? "TCP" : "UDP", rules_list[i].defined_fields);
	}
}

/* Функция для чтения файла /proc */
static ssize_t mynetmod_read(struct file *File, char __user *user_buf, size_t count, loff_t *offs)
{
	char buf[BUF_SIZE] = {0};

	get_stats(buf, BUF_SIZE);

	// char text[] = "Someday I'll make statistics and display them. Someday... \n";
	int to_copy, not_copied, delta;

	/* Узнаём сколько будем передавать в userspace */
	to_copy = min(count, sizeof(buf));
	
	/* Передаём информацию */
	not_copied = copy_to_user(user_buf, buf, to_copy);

	/* Вычисляем сколько осталось передать */
	delta = to_copy - not_copied;

	return delta;
}

/* Функция инициализации модуля ядра */
static int __init mynetmod_init(void)
{
	umode_t proc_mod = 0444; /* ugo+r */

	/* Создание /proc/mynetnod/bl_stats */
	proc_folder = proc_mkdir("mynetmod", NULL);
	if (proc_folder == NULL)
	{
		pr_alert("mynetmod : ERROR - proc_mkdir(\"mynetmod\", ...)\n");
		return -ENOMEM;
	}

	proc_file = proc_create("bl_stats", proc_mod, proc_folder, &pops);
	if (proc_folder == NULL)
	{
		pr_alert("mynetmod : ERROR - proc_create(\"bl_stats\", ...);\n");
		proc_remove(proc_folder);
		return -ENOMEM;
	}
	pr_info("mynetmod : self folder and files in procfs are created\n");

	/* Получаем major num для устройства */
	major = register_chrdev(0, DEVICE_NAME, &fops);
	minor = 0;
	if (major < 0)
	{
		pr_alert("mynetmod : register chardev failed with %d\n", major);
		return major;
	}

	/* Создаём файл в /dev */
	cls = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(cls, NULL, MKDEV(major, minor), NULL, DEVICE_NAME);
	pr_info("mynetmod : device created on /dev/%s\n", DEVICE_NAME);

	/* Инициализация rules_list */
	init_rules_list();

	/* Добавим тестовое правило 
	 * ipsrc : 127.0.0.1
	 * portsrc : 8080
	 * proto : udp
	 */
	/*struct kern_rule test_rule;
	memset(&test_rule, 0, sizeof(struct kern_rule));
	test_rule.src_ip.s_addr = 16777343; //127.0.0.1
	test_rule.src_port = 8080;
	test_rule.proto = IPPROTO_UDP;
	rules_list[0] = test_rule;
	rules_count++;
	*/

	/* Выделяем память для хуков */
	nf_tracer_ops = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL | __GFP_ZERO);
	nf_tracer_out_ops = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL | __GFP_ZERO);

	if (!nf_tracer_ops || !nf_tracer_out_ops) 
	{
		pr_alert("mynetmod: Memory allocation failed\n");
		kfree(nf_tracer_ops);
		kfree(nf_tracer_out_ops);
		return -ENOMEM;
	}

	/* Регистрируем хуки */
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
	/* Удаляем proc файл и директорию */
	proc_remove(proc_file);
	proc_remove(proc_folder);

	/* Освобождаем девайс */
	unregister_chrdev(major, DEVICE_NAME);
	device_destroy(cls, MKDEV(major, minor));
	class_destroy(cls);

	/* Освобождаем память от хуков */
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