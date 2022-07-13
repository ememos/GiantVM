#include <linux/list.h>

struct list_param {
	struct list_head *arg[2];
};

void* cc_list_move(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_move(list_param->arg[0], list_param->arg[1]);
	return NULL;
}

void* cc_list_move_tail(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_move_tail(list_param->arg[0], list_param->arg[1]);
	return NULL;
}


void* cc_list_del(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_del(list_param->arg[0]);
	return NULL;
}

void* cc_list_del_init(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_del_init(list_param->arg[0]);
	return NULL;
}

void* cc_list_add(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_add(list_param->arg[0], list_param->arg[1]);
	return NULL;
}

void* cc_list_add_tail(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_add_tail(list_param->arg[0], list_param->arg[1]);
	return NULL;
}

void* cc_list_replace(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_replace(list_param->arg[0], list_param->arg[1]);
	return NULL;
}

void* cc_list_replace_init(void *params) {
	struct list_param *list_param;

	list_param = (struct list_param *)params;
	list_replace_init(list_param->arg[0], list_param->arg[1]);
	return NULL;
}
struct list_head cc_head __attribute__((aligned(4096))) = LIST_HEAD_INIT(cc_head);
struct list_head spin_head __attribute__((aligned(4096))) = LIST_HEAD_INIT(spin_head);

#define LIST_LEN 2000
