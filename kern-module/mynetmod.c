/* Данный модуль является драйвером устройства
 *
 */
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h> // module_init/exit
#include <linux/kernel.h> // для sprintf
#include <linux/module.h> // Для всех модулей ядра
#include <linux/printk.h> // Средство вывода в ядре
#include <linux/types.h>
#include <linux/uaccess.h> // для get_user и put_user 
#include <linux/version.h>

#include <asm/errno.h>

#include "/home/pavletsov21/eltex/knm/common/ioctl_cmd.h"

MODULE_AUTHOR("Pavletsov Feodor");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Network module + fulter");

static int add_filter_rule(struct kern_rule);

// Функция выолняемая при открытии файла файла устройства
static int driver_open(struct inode *device_file, struct file *instance);
// Функция выолняемая при закрытии файла файла устройства 
static int driver_release(struct inode *device_file, struct file *instance);
// Функция для управления драйвером через ioctl
static long int my_ioctl(struct file *file, unsigned cmd, unsigned long arg);

#define DEVICE_NAME "mynetmod" // Название драйвера в /dev
// #define BUF_SIZE 80 // Данный параметр берётся из ioctl_cmd.h

// major нужен как уникальный номер устройства для опознавания ядром
static int major;

enum {
    CDEV_NOT_USED,
    CDEV_EXCLUSIVE_OPEN,
};

// Используется для предотварщения одновременного множественного использования
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char msg[BUF_SIZE + 1];

static struct class *cls;

// Определяем действия с файлом
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = driver_open, 
	.release = driver_release,
	.unlocked_ioctl = my_ioctl
};

#define RULES_NUM 10

static struct kern_rule rules[RULES_NUM];

// Функция вызываемая при инициализации модуля
static int __init mynetmod_init(void)
{
	// Определяем major для модуля
	major = register_chrdev(0, DEVICE_NAME, &fops);

	if (major < 0)
	{
		pr_alert("Register chardev failed with %d\n", major);
		return major;
	}
	pr_info("mynetmod getted major number = %d", major);

	// Создаём файл модуля в /dev
	cls = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	pr_info("Device create on /dev/%s\n", DEVICE_NAME);

	pr_info("Hello world by mynetmod!\n");
	return 0;
}

// Функция вызываемая при удалении модуля
static void __exit mynetmod_exit(void)
{
	pr_info("Goodbye World by myinitmod!\n");
}

static int driver_open(struct inode *device_file, struct file *instance)
{
	printk("mynetmod - open was called");
	return 0;
}

static int driver_release(struct inode *device_file, struct file *instance)
{
	printk("mynetmod - close was open");
	return 0;
}

static long int my_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	// В эту переменную ядро запишет команду от пользователя
	struct kern_cmd user_cmd;

	switch(cmd)
	{
		case ADD_RULE:
			if (copy_from_user(&user_cmd, (struct kern_cmd *)arg, sizeof(user_cmd)))
			{
				printk("mynetmod - Error copying kern command from user.\n");
				break;
			} 
			printk("mynetmod - Kern commmand was succsessfuly copied from user");
			break;
		case DEL_RULE:
			if (copy_to_user((struct kern_cmd *)arg, &user_cmd,  sizeof(user_cmd)))
			{
				printk("mynetmod - Error copying kern command to user.\n");
				break;
			}
			printk("mynetmod - Kern commmand was succsessfuly copied to user.\n");
			break;
		case SHOW:
			if (copy_from_user(&test, (struct mystruct *)arg, sizeof(test)))
			{
				printk("mynetmod - Error copying data from user.\n");
				break;
			}
			printk("mynetmod - Statistic was succsessfuly gived to userspace");
			break;
		default:
			break;
	}

	return 0;
}

// Объявляем какие функции используются для
// инициализации и удаления модуля
module_init(mynetmod_init);
module_exit(mynetmod_exit);