#include "/home/pavletsov21/eltex/knm/kern-module/src/rules_list.h"

int init_rules_list(struct head_rule_node_t *head)
{
	head->next = NULL;
	head->prev = NULL;

	head->rules_count = 0;
}

/* Алгоритм desturct_rules_list
 * Пока (head->next != NULL)
 * 1. Удалить head->next
 * 2. Конец итерации
 * 3. 
 */
int desturct_rules_list(struct rule_node_t *head)
{
	while (head->next != NULL)
		free(head->next);

	free(head);

	return 1;
}

int add_rule_tail(struct rule_node_t *head, struct rule_node_t *rule)
{
	/* Если хвост пуст, значит в списке вообще нет элементов кроме головы */
	if (head->prev == NULL)
	{
		head->prev = rule;
		head->next = rule;
		return 1;
	}

	struct rule_node_t *it = head->prev;

	it->next = rule;
	head->prev = rule;
	rule->prev = it;
	rule->next = head;

	return 1;
}

int add_rule_head(struct rule_node_t *head, struct rule_node_t *rule)
{
	/* Если next пуст, значит в списке вообще нет элементов кроме головы */
	if (head->next == NULL)
	{
		head->next = rule;
		head->prev = rule;
		return 1;
	}

	struct rule_node_t *it = head->next;

	head->next = rule;
	it->prev = rule;
	rule->next = it;
	rule->prev = head;

	return 1;
}

int remove_rule(struct rule_node_t *head, struct rule_node_t *rule)
{
	if (rule == head) return -1;

	struct rule_node_t *itnext = rule->next;
	struct rule_node_t *itprev = rule->prev;

	itprev->next = itnext;
	itnext->prev = itprev;

	free(rule);
	return 1;
}

int find_rule(struct rule_node_t *head, struct rule_node_t *ref, struct rule_node_t *res)
{
	struct rule_node_t *it = head->next;

	while (it != NULL) 
	{
		if (memcmp(&it->rule, &ref->rule, sizeof(struct kern_rule))); 
		{
			res = it;
			return 1;
		}
		it = it->next;
	}

	return -1;
}