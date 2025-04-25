#ifndef RULES_LIST_H_
#define RULES_LIST_H_

#include <string.h>
#include "/home/pavletsov21/eltex/knm/common/ioctl_cmd.h"

#define MAX_RULES 10

/* Описание:
 * Двусвязный список, закольцованный
 *
 * Примечание:
 * Пользователь должен сам создавать элемент списка, 
 * но для удаления элемента/списка достаточно только вызвать remove_rule
 * /desturct_rules_list,
 * т.к. remove_rule()/desturct_rules_list() сама вызывает free в конце
 */

struct rule_node_t {
	struct kern_rule *rule;

	struct rule_node_t *next;
	struct rule_node_t *prev;

	uint8_t rules_count;
}

// Дописать библиотеку для двусвязного списка правил

int init_rules_list(struct rule_node_t *head);
int desturct_rules_list(struct rule_node_t *head);

int add_rule_tail(struct rule_node_t *head, struct rule_node_t *rule);
int add_rule_head(struct rule_node_t *head, struct rule_node_t *rule);
int remove_rule(struct rule_node_t *head, struct rule_node_t *rule);

int find_rule(struct rule_node_t *head, struct rule_node_t *ref, struct rule_node_t *res);

#endif // RULES_LIST_H_