#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/threads.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/dynamic_debug.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/processor.h>
#include <asm/barrier.h>

MODULE_DESCRIPTION("Simple Lock benchmark module");
MODULE_AUTHOR("Wonhyuk Yang");
MODULE_LICENSE("GPL");

#define MAX_COMBINER_OPERATIONS 5

/* CPU number and index are encoded in cc_node.next
 * Now, each cpu has two node and these nodes are
 * used alternatley. In this way, we can avoid
 * node overwrite problem.
 */
#define INDEX_SHIFT			(1)
#define INDEX_MASK			((1 << INDEX_SHIFT) - 1)
#define ENCODE_NEXT(x, y)	((x << INDEX_SHIFT) | (y & INDEX_MASK))

#define DECODE_IDX(x)		(x & INDEX_MASK)
#define DECODE_CPU(x)		(x >> INDEX_SHIFT)

#define GET_NEXT_NODE(x, y)	(per_cpu(x, DECODE_CPU(y)) + DECODE_IDX(y))

typedef void* (*request_t)(void *);
int prepare_tests(void);

struct cc_node {
	request_t req;
	void* params;
	void* ret;
	bool wait;
	bool completed;
	int prev;
	int next;
	atomic_t refcount;
};

DEFINE_PER_CPU(struct cc_node, node_array[2]) = {
	{
		.req = NULL,
		.params = NULL,
		.ret = NULL,
		.wait = false,
		.completed = false,
		.prev = ENCODE_NEXT(NR_CPUS, 0),
		.next = ENCODE_NEXT(NR_CPUS, 1),
		.refcount = ATOMIC_INIT(0),
	},
	{
		.req = NULL,
		.params = NULL,
		.ret = NULL,
		.wait = false,
		.completed = false,
		.prev = ENCODE_NEXT(NR_CPUS, 1),
		.next = ENCODE_NEXT(NR_CPUS, 0),
		.refcount = ATOMIC_INIT(0),
	},
};

struct lb_info {
	request_t req;
	void *params;
	atomic_t *lock;
	int counter;
	bool monitor;
	bool quit;
};

DEFINE_PER_CPU(struct lb_info, lb_info_array);
DEFINE_PER_CPU(struct task_struct *, task_array);

/* At first, lock is NULL value. This mean pointing the
 * CPU 0, idx 0. Thus, To make it consistent node_array_idx
 * should be set 1
 */
DEFINE_PER_CPU(int, node_array_idx) = 1;

void* execute_cs(request_t req, void *params, atomic_t *lock)
{
	struct cc_node *prev, *pending;
	struct cc_node *next;
	int counter = 0;
	unsigned int this_cpu = get_cpu();
	unsigned int pending_cpu;
	unsigned int prev_cpu;

	/* get/update node_arra_idx */
	int this_cpu_idx = per_cpu(node_array_idx, this_cpu);
	per_cpu(node_array_idx, this_cpu) = this_cpu_idx? 0 : 1;

	this_cpu = ENCODE_NEXT(this_cpu, this_cpu_idx);
	next = GET_NEXT_NODE(node_array, this_cpu);
	next->req = NULL;
	next->params = NULL;
	next->ret = NULL;
	next->wait = true;
	next->completed = false;
	next->next = ENCODE_NEXT(NR_CPUS, 0);
	smp_wmb();

	atomic_inc(&next->refcount);
	prev_cpu = atomic_xchg(lock, this_cpu);
	WARN(prev_cpu == this_cpu, "lockbench: prev_cpu == this_cpu, Can't be happend!!!");
	next->prev = prev_cpu;

	prev = GET_NEXT_NODE(node_array, prev_cpu);
	/* request and parameter should be set. Then, next should be set */
	WRITE_ONCE(prev->req, req);
	WRITE_ONCE(prev->params, params);
	smp_wmb();
	WRITE_ONCE(prev->next, this_cpu);

	/* Failed to get lock */
	pr_debug("lockbench: prev{CPU: (%d, %d), wait:%d, completed:%d}\n"
					"lockbench: next{CPU: (%d, %d), wait:%d, completed:%d}\n",
					DECODE_CPU(prev_cpu), DECODE_IDX(prev_cpu),
					prev->wait, prev->completed,
					DECODE_CPU(this_cpu), DECODE_IDX(this_cpu),
					next->wait, next->completed);

	pr_debug("lockbench: Spinning start!\n");
	while (READ_ONCE(prev->wait))
		cpu_relax();

	if (READ_ONCE(prev->completed)) {
		atomic_dec(&next->refcount);
		put_cpu();
		pr_debug("lockbench: <Normal thread> CPU: (%d, %d) end of critical section!\n",
						DECODE_CPU(this_cpu), DECODE_IDX(this_cpu));
		return prev->ret;
	}

	/* Success to get lock */
	pending_cpu = prev_cpu;

	while (counter++ < MAX_COMBINER_OPERATIONS) {
		pending = GET_NEXT_NODE(node_array, pending_cpu);
		pending_cpu = READ_ONCE(pending->next);
		/* Keep ordering next -> (req, params)*/
		smp_mb();

		/* Branch prediction: which case is more profitable? */
		if (DECODE_CPU(pending_cpu) == NR_CPUS)
			goto out;

		pr_debug("lockbench: CPU: (%d, %d), next_cpu: (%d, %d), request: %pF\n",
						DECODE_CPU(pending_cpu), DECODE_IDX(pending_cpu),
						DECODE_CPU(pending->next), DECODE_IDX(pending->next),
						pending->req);

		/* Preserve store order completed -> wait -> next */
		WARN(pending->req == NULL, "lockbench: pending->req == NULL...");
		pending->ret = pending->req(pending->params);
		WRITE_ONCE(pending->completed, true);
		WRITE_ONCE(pending->wait, false);
	}
	/* Pass tho combiner thread role */
	WARN(DECODE_CPU(pending_cpu) == NR_CPUS, "lockbench: DECODE_CPU(pedning_cpu) == NR_CPUS...");
	pr_debug("lockbench: pass the combiner role to CPU: (%d, %d)\n",
					DECODE_CPU(pending_cpu), DECODE_IDX(pending_cpu));

	pending = GET_NEXT_NODE(node_array, pending_cpu);
out:
	pending->wait = false;
	atomic_dec(&next->refcount);
	put_cpu();
	pr_debug("lockbench: <Combiner thread> end of critical section!\n");
	return prev->ret;
}

/* Dummy workload */
atomic_t dummy_lock = ATOMIC_INIT(0);
int dummy_counter = 0;
void* dummy_increment(void* params)
{
	int *counter = (int*)params;
	if (unlikely(counter == NULL)) {
		printk("!!!! counter: %p", (counter));
	} else {
		(*counter)++;
	}
	return params;
}

/* Debugfs */
static int
lb_open(struct inode *inode, struct file *filep)
{
	return 0;
}

static int
lb_release(struct inode *inode, struct file *filep)
{
	return 0;
}

static ssize_t lb_write(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	unsigned long val;
	int ret;
	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;

	if (val == 1) {
		prepare_tests();
	}
	(*ppos)++;
	return cnt;
}

static ssize_t lb_quit(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	unsigned long val;
	int ret, cpu;
	struct lb_info *ld;
	struct cc_node *node;
	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;

	if (val == 1) {
		dummy_lock.counter = ENCODE_NEXT(0, 0);
		for_each_online_cpu(cpu) {
			ld = &per_cpu(lb_info_array, cpu);
			ld->quit = true;

			smp_mb();
			node = per_cpu(node_array, cpu);
			node[0].wait = false;
			node[0].completed = true;
			node[1].wait = false;
			node[1].completed = true;
		}
		per_cpu(node_array, 0)[0].completed = false;
	}
	(*ppos)++;
	return cnt;
}

static void *t_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *t_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void t_stop(struct seq_file *m, void *v)
{
}

static int t_show(struct seq_file *m, void *v)
{
	int cpu, idx;
	struct cc_node *node;

	seq_printf(m, "<Node_array information>\n");
	seq_printf(m, "dummy_lock: (%d, %d)\n",
					DECODE_CPU(dummy_lock.counter), DECODE_IDX(dummy_lock.counter));
	for_each_online_cpu(cpu) {
		node = per_cpu(node_array, cpu);
		idx = per_cpu(node_array_idx, cpu);
		seq_printf(m, "Node idx: %d\n", idx);
		seq_printf(m, "Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %lld,\n"
						"\tNext (%d, %d)\n"
						"\tPrev (%d, %d)\n}\n",
						cpu, 0,
						node[0].req, node[0].params,
						node[0].wait, node[0].completed,
						node[0].refcount,
						DECODE_CPU(node[0].next),
						DECODE_IDX(node[0].next),
						DECODE_CPU(node[0].prev),
						DECODE_IDX(node[0].prev));
		seq_printf(m, "Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %lld,\n"
						"\tNext (%d, %d)\n"
						"\tPrev (%d, %d)\n}\n",
						cpu, 1,
						node[1].req, node[1].params,
						node[1].wait, node[1].completed,
						node[1].refcount,
						DECODE_CPU(node[1].next),
						DECODE_IDX(node[1].next),
						DECODE_CPU(node[1].prev),
						DECODE_IDX(node[1].prev));
	}

	return 0;
}

static const struct seq_operations show_status_seq_ops= {
	.start		= t_start,
	.next		= t_next,
	.stop		= t_stop,
	.show		= t_show,
};

static int lb_status_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &show_status_seq_ops);
	if (ret) {
		return ret;
	}

	m = file->private_data;
	return 0;
}

static int lb_status_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static const struct file_operations lb_trigger_fops = {
	.open	 = lb_open,
	.read	 = NULL,
	.write   = lb_write,
	.release = lb_release,
	.llseek  = NULL,
};

static const struct file_operations lb_quit_fops = {
	.open	 = lb_open,
	.read	 = NULL,
	.write   = lb_quit,
	.release = lb_release,
	.llseek  = NULL,
};

static const struct file_operations lb_status_fops= {
	.open	 = lb_status_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lb_status_release,
};

static struct dentry *lb_debugfs_root;

static int lb_debugfs_init(void)
{
	lb_debugfs_root = debugfs_create_dir("lock_benchmark", NULL);

	debugfs_create_file("trigger", 0200,
					lb_debugfs_root, NULL, &lb_trigger_fops);
	debugfs_create_file("quit", 0200,
					lb_debugfs_root, NULL, &lb_quit_fops);
	debugfs_create_file("status", 0400,
					lb_debugfs_root, NULL, &lb_status_fops);

	return 0;
}

static int lb_debugfs_exit(void)
{
	debugfs_remove_recursive(lb_debugfs_root);
	return 0;
}

int test_thread(void *data)
{
	int i;
	struct lb_info * lb_data = (struct lb_info *)data;
	int cpu = get_cpu();
	unsigned long prev, cur;

	prev = sched_clock();
	for (i=0; i<lb_data->counter && !READ_ONCE(lb_data->quit); i++) {
		if (unlikely(lb_data->monitor && i && ((i % 1000)==0))) {
			cur = sched_clock();
			printk("lockbench: monitor thread %dth [%lu]\n", i, cur-prev);
			prev = cur;
		}
		execute_cs(lb_data->req, lb_data->params, lb_data->lock);
	}

	cur = sched_clock();
	printk("lockbench: monitor thread %dth [%lu]\n", i, cur-prev);

	per_cpu(task_array, cpu) = NULL;
	put_cpu();
	return 0;
}

int prepare_tests(void)
{
	struct task_struct *thread;
	struct lb_info *li;
	bool monitor_thread = true;
	int cpu;
	int max_cpus = 3;
	int nr_cpus = 0;

	for_each_online_cpu(cpu) {
		thread = per_cpu(task_array, cpu);
		if (thread != NULL) {
			pr_debug("lockbench: test is progressing!\n");
			return 1;
		}
	}

	for_each_online_cpu(cpu) {
		if (nr_cpus++ >= max_cpus)
			break;

		li = &per_cpu(lb_info_array, cpu);
		li->req = dummy_increment;
		li->params = &dummy_counter;
		li->lock = &dummy_lock;
		li->counter = 1000 * 10;
		li->monitor = monitor_thread;

		thread = kthread_create(test_thread, (void *)li, "lockbench/%u", cpu);
		if (IS_ERR(thread)) {
			pr_err("Failed to create kthread on CPU %u\n", cpu);
			continue;
		}
		kthread_bind(thread, cpu);

		wake_up_process(thread);
		per_cpu(task_array, cpu) = thread;

		monitor_thread = false;
	}
	return 0;
}

/* module init/exit */
static int lock_benchmark_init(void)
{
	lb_debugfs_init();
	return 0;
}

static void lock_benchmark_exit(void)
{
	int cpu;
	struct lb_info *ld;
	struct cc_node *node;

	for_each_online_cpu(cpu) {
		ld = &per_cpu(lb_info_array, cpu);
		ld->quit = true;

		smp_mb();
		node = per_cpu(node_array, cpu);
		node[0].wait = false;
		node[0].completed = true;
		node[1].wait = false;
		node[1].completed = true;
	}
	lb_debugfs_exit();
}

module_init(lock_benchmark_init);
module_exit(lock_benchmark_exit);
