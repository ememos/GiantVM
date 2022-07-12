#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/threads.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/cache.h>
#include <linux/dynamic_debug.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/processor.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>
#include "list_bench.h"

MODULE_DESCRIPTION("Simple Lock benchmark module");
MODULE_AUTHOR("Wonhyuk Yang");
MODULE_LICENSE("GPL");

//#define DEBUG
//#define BLOCK_IRQ
#define DYNAMIC_PERCPU
#define NR_BENCH	(5000000)
#define NR_SAMPLE	1000

#define MAX_COMBINER_OPERATIONS 1

#define MAX_CPU		32
#define MAX_DELAY 	10000

static int max_cpus = 31;
static int delay_time = 100;
static int nr_bench = 500000<<1;
static int thread_switch = 0;

static unsigned long perf_result[NR_BENCH/NR_SAMPLE];
/* CPU number and index are encoded in cc_node.next
 * Now, each cpu has two node and these nodes are
 * used alternatley. In this way, we can avoid
 * node overwrite problem.
 */
#define INDEX_SHIFT			(1)
#define INDEX_SIZE			(1<<INDEX_SHIFT)
#define INDEX_MASK			(INDEX_SIZE - 1)
#define ENCODE_NEXT(x, y)	((x << INDEX_SHIFT) | (y & INDEX_MASK))

#define DECODE_IDX(x)		(x & INDEX_MASK)
#define DECODE_CPU(x)		(x >> INDEX_SHIFT)

#define GET_NEXT_NODE(x, y)	(per_cpu_ptr(x, DECODE_CPU(y)) + DECODE_IDX(y))

#define GVM_CACHE_BYTES		(1<<12)
#define arch_lock_xchg(ptr, v)	__xchg_op((ptr), (v), xchg, "lock; ")

/* NUMA awareness structure */
struct cc_lock {
	spinlock_t global_lock __attribute__((aligned(GVM_CACHE_BYTES)));
	atomic_t *node_lock_array[MAX_NUMNODES] __attribute__((aligned(GVM_CACHE_BYTES)));
} dummy_cclock;

void init_cclock (struct cc_lock *cclock) {
	int node;
	int i;
	int cpu;
	atomic_t *node_lock;
	struct page *page;

	spin_lock_init(&cclock->global_lock);

	for (i=0; i<MAX_NUMNODES; i++)
		cclock->node_lock_array[i] = NULL;

	for_each_node_state(node, N_MEMORY) {
		printk("Node:%d", node);
		page = alloc_pages_node(node, GFP_KERNEL| __GFP_ZERO, get_order(sizeof(struct cc_lock)));
		node_lock = (atomic_t *)page_to_virt(page);
		for_each_online_cpu(cpu) {
			if (cpu_to_node(cpu)==node) {
				node_lock->counter = ENCODE_NEXT(cpu, 0);
				break;
			}

		}
		cclock->node_lock_array[node] = node_lock;
	}
}

void exit_cclock (struct cc_lock *cclock) {
	int i;
	atomic_t *node_lock;	

	for (i=0; i<MAX_NUMNODES; i++) {
		node_lock = cclock->node_lock_array[i];
		if (node_lock)
			free_pages((unsigned long)node_lock, 0);	
	}
}

static inline atomic_t *get_node_lock(struct cc_lock *lock, int cpu) {
	int node;

	node = cpu_to_node(cpu);
	return lock->node_lock_array[node];	
}


static inline int atomic_lock_xchg(atomic_t *v, int new)
{
	int val;
	do {
		val = v->counter;
	} while (atomic_cmpxchg(v, val, new) != val);
	return val;
	//return arch_lock_xchg(&v->counter, new);
}
typedef void* (*request_t)(void *);
typedef int (*test_thread_t)(void *);

int prepare_tests(test_thread_t, void *, const char *);
int test_thread(void *data);
int test_thread2(void *data);
int list_bench(void *data);
int list_bench2(void *data);

#define CC_STAT_LOCK	(1<<0)
#define CC_STAT_DONE	(1<<1)

struct cc_node {
	struct cc_node *next;
	int idx;
	request_t req;
	void* params;
	atomic_t refcount;
	int status;
	void* ret;
} __attribute__((aligned(GVM_CACHE_BYTES)));

#ifdef DYNAMIC_PERCPU
struct cc_node __percpu *node_array __attribute__((aligned(GVM_CACHE_BYTES)));
#else
DEFINE_PER_CPU(struct cc_node, node_array[INDEX_SIZE]);
#endif

struct lb_info {
	request_t req;
	void *params;
	void *lock;
	int counter;
	bool monitor;
	bool quit;
};

DEFINE_PER_CPU(struct lb_info, lb_info_array);
DEFINE_PER_CPU(struct task_struct *, task_array);

static inline bool is_tail(struct cc_node *node, atomic_t *lock)
{
	struct cc_node *tmp = GET_NEXT_NODE(node_array, lock->counter);
	return tmp == node;
}

void* execute_cs(request_t req, void *params, struct cc_lock *lock)
{
	struct cc_node *prev, *pending;
	struct cc_node *next_pending;
	struct cc_node *next;
	int counter = 0;
	int status;
	atomic_t *node_lock;
	unsigned int this_cpu = get_cpu();
	unsigned int prev_cpu;
	request_t pending_req;
	int this_cpu_idx;
	
	/* grab node lock */
	node_lock = get_node_lock(lock, this_cpu);

	/* get/update node_arra_idx */
	this_cpu_idx = per_cpu_ptr(node_array, this_cpu)[0].idx++;

	this_cpu = ENCODE_NEXT(this_cpu, this_cpu_idx & INDEX_MASK);
	next = GET_NEXT_NODE(node_array, this_cpu);

	/* Wait for spinning thread */
	while (READ_ONCE(next->refcount.counter))
		cpu_relax();

	next->req = NULL;
	next->params = NULL;
	next->ret = NULL;
	next->status = CC_STAT_LOCK;
	next->next = NULL;
	smp_wmb();
	
	prev_cpu = atomic_lock_xchg(node_lock, this_cpu);
	prev = GET_NEXT_NODE(node_array, prev_cpu);
	/* request and parameter should be set. Then, next should be set */
	prev->req = req;
	prev->params = params;
	smp_wmb();

	atomic_inc(&prev->refcount);
	WRITE_ONCE(prev->next, next);

	while (1) {
		status = READ_ONCE(prev->status);
		if (status & CC_STAT_LOCK)
			cpu_relax();
		else 
			break;
	}

	smp_rmb();
	if (status & CC_STAT_DONE) {
		atomic_dec(&prev->refcount);
		put_cpu();
		return prev->ret;
	}

	/* Success to get lock */
	pending = prev;
	
	/* Get global lock */
retry:
	if (!spin_trylock(&lock->global_lock)) {
		udelay(delay_time);
		goto retry;
	}

	while (counter++ < MAX_COMBINER_OPERATIONS*max_cpus) {
		next_pending = READ_ONCE(pending->next);

		/* Branch prediction: which case is more profitable? */
		if (next_pending == NULL)
			goto out;

		/* Keep ordering next -> (req, params)*/
		smp_rmb();
		pending_req = READ_ONCE(pending->req);

		/* Preserve store order completed -> status -> next */
		WRITE_ONCE(pending->ret, pending_req(READ_ONCE(pending->params)));
		WRITE_ONCE(pending->status, CC_STAT_DONE);
		pending = next_pending;
	}
out:
	/* Release global lock */
	spin_unlock(&lock->global_lock);

	smp_wmb();
	atomic_dec(&prev->refcount);
	WRITE_ONCE(pending->status, 0);
	put_cpu();
	return prev->ret;
}

/* Dummy workload */
__attribute__((aligned(GVM_CACHE_BYTES))) DEFINE_SPINLOCK(dummy_spinlock);
atomic_t dummy_lock __attribute__((aligned(GVM_CACHE_BYTES))) = ATOMIC_INIT(0);
int dummy_counter __attribute__((aligned(GVM_CACHE_BYTES))) = 0;
int cache_table[1024*4+1];
void* dummy_increment(void* params)
{
	int i;
	int *counter = (int*)params;
	(*counter)++;
	return NULL;
	for (i = 0; i < 0; i++)
		cache_table[i*1024]++;

	if (delay_time)
		udelay(delay_time);
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
	int cpu;
	struct lb_info *li;
	bool monitor_thread = true;

	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);
	if (ret)
		return ret;

	WRITE_ONCE(thread_switch, 0);
	if (val == 1) {
		for_each_online_cpu(cpu) {
			li = &per_cpu(lb_info_array, cpu);
			li->req = dummy_increment;
			li->params = &dummy_counter;
			li->lock = (void *)&dummy_cclock;
			li->counter = nr_bench;
			li->monitor = monitor_thread;
			monitor_thread = false;
		}
		prepare_tests(test_thread, (void *)&lb_info_array, "cc-lockbench");
	} else if (val == 2) {
		for_each_online_cpu(cpu) {
			li = &per_cpu(lb_info_array, cpu);
			li->req = dummy_increment;
			li->params = &dummy_counter;
			li->lock = (void *)&dummy_spinlock;
			li->counter = nr_bench;
			li->monitor = monitor_thread;
			monitor_thread = false;
		}
		prepare_tests(test_thread2, (void *)&lb_info_array, "spinlockbench");
	}
	else if (val == 3) {
		for_each_online_cpu(cpu) {
			li = &per_cpu(lb_info_array, cpu);
			li->lock = (void *)&dummy_cclock;
			li->counter = nr_bench;
			li->monitor = monitor_thread;
			monitor_thread = false;
		}
		prepare_tests(list_bench, (void *)&lb_info_array, "cc-list");
	} else if (val == 4) {
		for_each_online_cpu(cpu) {
			li = &per_cpu(lb_info_array, cpu);
			li->lock = (void *)&dummy_spinlock;
			li->counter = nr_bench;
			li->monitor = monitor_thread;
			monitor_thread = false;
		}
		prepare_tests(list_bench2, (void *)&lb_info_array, "spin-list");
	}

	(*ppos)++;
	udelay(1000);
	WRITE_ONCE(thread_switch, 1);
	return cnt;
}

static ssize_t lb_quit(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	unsigned long val;
	int ret, cpu;
	int j;
	struct lb_info *ld;
	struct cc_node *node;
	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;

	if (val == 1) {
		dummy_lock.counter = 0;
		for_each_online_cpu(cpu) {
			ld = &per_cpu(lb_info_array, cpu);
			ld->quit = true;

			smp_mb();
			node = per_cpu_ptr(node_array, cpu);
			for (j=0; j<INDEX_SIZE; j++) {
				node[j].status = CC_STAT_DONE;
			}
		}
		per_cpu_ptr(node_array, 0)[0].status = 0;
	}
	(*ppos)++;
	return cnt;
}

static ssize_t lb_cpu(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	int ret;
	unsigned long val;

	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;

	if (val > 0 && val < MAX_CPU)
		max_cpus = val;

	(*ppos)++;
	return cnt;
}

static ssize_t lb_bench(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	int ret;
	unsigned long val;

	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;

	if (val > 0 && val <= NR_BENCH)
		nr_bench = val;

	(*ppos)++;
	return cnt;
}

static ssize_t lb_delay(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	int ret;
	unsigned long val;
	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);

	if (ret)
		return ret;
	if (val >= 0 && val <= MAX_DELAY)
		delay_time = val;
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
	int cpu, idx, nid;
	struct cc_node *node;

	seq_printf(m, "<Node_array information>\n");

	for_each_node_state(nid, N_MEMORY) {
		seq_printf(m, "node_lock[%d]: (%d, %d)\n",
					nid, DECODE_CPU(dummy_cclock.node_lock_array[nid]->counter),
					DECODE_IDX(dummy_cclock.node_lock_array[nid]->counter));
	}

	for_each_online_cpu(cpu) {
		node = per_cpu_ptr(node_array, cpu);
		idx = node[0].idx;
		seq_printf(m, "Node idx: %d\n", idx);
		seq_printf(m, "Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %d,\n"
						"\tNext %px\n"
#ifdef DEBUG
						"\tPrev %px\n}\n",
#else
						,
#endif
						cpu, 0,
						node[0].req, node[0].params,
						node[0].status & CC_STAT_LOCK,
						node[0].status & CC_STAT_DONE,
						node[0].refcount.counter,
						node[0].next
#ifdef DEBUG
						,
						node[0].prev,
#endif
						);
		seq_printf(m, "Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %d,\n"
						"\tNext %px\n"
#ifdef DEBUG
						"\tPrev %px\n}\n",
#else
						,
#endif
						cpu, 0,
						node[1].req, node[1].params,
						node[1].status & CC_STAT_LOCK,
						node[1].status & CC_STAT_DONE,
						node[1].refcount.counter,
						node[1].next
#ifdef DEBUG
						,
						node[1].prev,
#endif
						);
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

static int r_show(struct seq_file *m, void *v)
{
	int cpu;
	struct task_struct *thread;

	for_each_online_cpu(cpu) {
		thread = per_cpu(task_array, cpu);
		if (thread) {
			seq_printf(m, "0");
			return 0;
		}
	}
	seq_printf(m, "1");
	return 0;
}

static const struct seq_operations show_ready_seq_ops= {
	.start		= t_start,
	.next		= t_next,
	.stop		= t_stop,
	.show		= r_show,
};

static int lb_ready_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &show_ready_seq_ops);
	if (ret) {
		return ret;
	}

	m = file->private_data;
	return 0;
}

static int lb_ready_release(struct inode *inode, struct file *file)
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
	.write   = lb_quit,
	.release = lb_release,
};

static const struct file_operations lb_cpu_fops = {
	.open	 = lb_open,
	.write   = lb_cpu,
	.release = lb_release,
};

static const struct file_operations lb_bench_fops = {
	.open	 = lb_open,
	.write   = lb_bench,
	.release = lb_release,
};

static const struct file_operations lb_delay_fops = {
	.open	 = lb_open,
	.write   = lb_delay,
	.release = lb_release,
};

static const struct file_operations lb_status_fops= {
	.open	 = lb_status_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lb_status_release,
};

static const struct file_operations lb_ready_fops= {
	.open	 = lb_ready_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lb_ready_release,
};

static struct dentry *lb_debugfs_root;

static int lb_debugfs_init(void)
{
	lb_debugfs_root = debugfs_create_dir("lock_benchmark", NULL);

	debugfs_create_file("trigger", 0200,
					lb_debugfs_root, NULL, &lb_trigger_fops);
	debugfs_create_file("quit", 0200,
					lb_debugfs_root, NULL, &lb_quit_fops);
	debugfs_create_file("cpu", 0200,
					lb_debugfs_root, NULL, &lb_cpu_fops);
	debugfs_create_file("nr_bench", 0200,
					lb_debugfs_root, NULL, &lb_bench_fops);
	debugfs_create_file("delay", 0200,
					lb_debugfs_root, NULL, &lb_delay_fops);
	debugfs_create_file("status", 0400,
					lb_debugfs_root, NULL, &lb_status_fops);
	debugfs_create_file("ready", 0400,
					lb_debugfs_root, NULL, &lb_ready_fops);


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
	int cpu = get_cpu();
#ifdef BLOCK_IRQ
	unsigned long flags;
#endif
	struct lb_info *lb_data = &per_cpu(lb_info_array, cpu);
	unsigned long prev = 0, cur;
	while(!READ_ONCE(thread_switch));

	if (unlikely(lb_data->monitor))
		prev = sched_clock();
	for (i=0; i<lb_data->counter && !READ_ONCE(lb_data->quit);i++) {
		if (unlikely(lb_data->monitor && i && (i%NR_SAMPLE==0))) {
			cur = sched_clock();
			perf_result[(i/NR_SAMPLE)-1] = cur-prev;
			prev = cur;
		}
#ifdef BLOCK_IRQ
		local_irq_save(flags);
#endif
		execute_cs(lb_data->req, lb_data->params, lb_data->lock);
#ifdef BLOCK_IRQ
		local_irq_restore(flags);
#endif
	}

	if (unlikely(lb_data->monitor)) {
		cur = sched_clock();
		perf_result[(i+NR_SAMPLE-1)/NR_SAMPLE-1] = cur-prev;
		for (i=0;i<lb_data->counter;i+=NR_SAMPLE)
			printk("lockbench: <cc-lock> monitor thread %dth [%lu]\n", i, perf_result[i/NR_SAMPLE]);
	}

	per_cpu(task_array, cpu) = NULL;
	put_cpu();
	return 0;
}
static inline void profile_spin(spinlock_t *lock, struct lb_info * lb_data) {
#ifdef BLOCK_IRQ
	unsigned long flags;
#endif

#ifdef BLOCK_IRQ
	spin_lock_irqsave(lock, flags);
#else
	spin_lock(lock);
#endif
	lb_data->req(lb_data->params);
#ifdef BLOCK_IRQ
	spin_unlock_irqrestore(lock, flags);
#else
	spin_unlock(lock);
#endif

}
int test_thread2(void *data)
{
	int i;
	int cpu = get_cpu();
	struct lb_info * lb_data = &per_cpu(*((struct lb_info *)data), cpu);
	unsigned long prev = 0, cur = 0;

	spinlock_t *lock = (spinlock_t *)lb_data->lock;
	while(!READ_ONCE(thread_switch));

	if (unlikely(lb_data->monitor))
		prev = sched_clock();
	for (i=0; i<lb_data->counter && !READ_ONCE(lb_data->quit); i++) {
		if (unlikely(lb_data->monitor && i && (i%NR_SAMPLE==0))) {
			cur = sched_clock();
			perf_result[(i/NR_SAMPLE)-1] = cur-prev;
			prev = cur;
		}
		profile_spin(lock, lb_data);
	}

	if (unlikely(lb_data->monitor)) {
		cur = sched_clock();
		perf_result[(i+NR_SAMPLE-1)/NR_SAMPLE-1] = cur-prev;
		for (i=0;i<lb_data->counter;i+=NR_SAMPLE)
			printk("lockbench: <spinlock> monitor thread %dth [%lu]\n", i, perf_result[i/NR_SAMPLE]);
	}

	per_cpu(task_array, cpu) = NULL;
	put_cpu();
	return 0;
}

int list_bench(void *data)
{
	int i, j;
	int cpu = get_cpu();
	unsigned long flags;
	struct lb_info *lb_data = &per_cpu(lb_info_array, cpu);
	struct list_head *list_node = kmalloc(sizeof(struct list_head)*LIST_LEN, GFP_KERNEL);
	struct list_param param;
	unsigned long prev = 0, cur;
	while(!READ_ONCE(thread_switch));

	if (unlikely(lb_data->monitor))
		prev = sched_clock();
	for (i=0; i<lb_data->counter && !READ_ONCE(lb_data->quit);i++) {
		if (unlikely(lb_data->monitor && i)) {
			cur = sched_clock();
			perf_result[i] = cur-prev;
			prev = cur;
		}

		param.arg[1] = &cc_head;
		for(j=0;j<LIST_LEN;j++) {
			param.arg[0] = list_node+j;

			local_irq_save(flags);
			execute_cs(cc_list_add, &param, lb_data->lock);
			local_irq_restore(flags);
			udelay(5);
		}

		for(j=0;j<LIST_LEN;j++) {
			param.arg[0] = list_node+j;

			local_irq_save(flags);
			execute_cs(cc_list_del, &param, lb_data->lock);
			local_irq_restore(flags);
			udelay(5);
		}
	}

	if (unlikely(lb_data->monitor)) {
		cur = sched_clock();
		perf_result[i] = cur-prev;
		for (i=0;i<lb_data->counter;i++)
			printk("lockbench: <cc-lock> monitor thread %dth [%lu]\n", i, perf_result[i]);
	}
	kfree(list_node);
	per_cpu(task_array, cpu) = NULL;
	put_cpu();
	return 0;
}

int list_bench2(void *data)
{
	int i, j;
	int cpu = get_cpu();
	unsigned long flags;
	struct lb_info *lb_data = &per_cpu(lb_info_array, cpu);
	spinlock_t *lock = (spinlock_t *)lb_data->lock;
	
	struct list_head *list_node = kmalloc(sizeof(struct list_head)*LIST_LEN, GFP_KERNEL);
	unsigned long prev = 0, cur;
	while(!READ_ONCE(thread_switch));

	if (unlikely(lb_data->monitor))
		prev = sched_clock();
	for (i=0; i<lb_data->counter && !READ_ONCE(lb_data->quit);i++) {
		if (unlikely(lb_data->monitor && i)) {
			cur = sched_clock();
			perf_result[i] = cur-prev;
			prev = cur;
		}

		for(j=0;j<LIST_LEN;j++) {
			spin_lock_irqsave(lock, flags);
			list_add(list_node+j, &spin_head);
			spin_unlock_irqrestore(lock, flags);
			udelay(5);
		}

		for(j=0;j<LIST_LEN;j++) {
			spin_lock_irqsave(lock, flags);
			list_del(list_node+j);
			spin_unlock_irqrestore(lock, flags);
			udelay(5);
		}
	}

	if (unlikely(lb_data->monitor)) {
		cur = sched_clock();
		perf_result[i] = cur-prev;
		for (i=0;i<lb_data->counter;i++)
			printk("lockbench: <spin-lock> monitor thread %dth [%lu]\n", i, perf_result[i]);
	}
	kfree(list_node);
	per_cpu(task_array, cpu) = NULL;
	put_cpu();
	return 0;
}

int prepare_tests(test_thread_t test, void *arg, const char *name)
{
	struct task_struct *thread;
	int cpu;
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

		thread = kthread_create(test, arg, "%s/%u", name, cpu);
		if (IS_ERR(thread)) {
			pr_err("Failed to create kthread on CPU %u\n", cpu);
			continue;
		}
		kthread_bind(thread, cpu);

		wake_up_process(thread);
		per_cpu(task_array, cpu) = thread;
	}
	return 0;
}
#ifdef DEBUG
static int dump_cclock(void)
{
	int cpu, idx;
	int j;
	struct cc_node *node;
	struct lb_info *ld;
	int tmp;

	pr_err("<Node_array information>\n");
	pr_err("dummy_lock: (%d, %d)\n",
					DECODE_CPU(dummy_lock.counter), DECODE_IDX(dummy_lock.counter));
	pr_err("last used node:\n");
	for (idx=6; idx>0; idx--){
		tmp = node_trace[(node_trace_idx + (MAX_CPU*2) - (idx)) % (MAX_CPU*2)];
		pr_err("(%d,%d)->", DECODE_CPU(tmp), DECODE_IDX(tmp));
	}
	for_each_online_cpu(cpu) {
		node = per_cpu_ptr(node_array, cpu);
		idx = node[0].idx;
		pr_err("Node idx: %d\n", idx);
		pr_err("Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %d,\n"
						"\tNext %px\n"
						"\tPrev %px\n}\n",
						cpu, 0,
						node[0].req, node[0].params,
						node[0].status & CC_STAT_LOCK, 
						node[0].status & CC_STAT_DONE,
						node[0].refcount.counter,
						node[0].next,
						node[0].prev
						);
		pr_err("Node(%d, %d) {\n"
						"\treq = %pF,\n"
						"\tparams = %p,\n"
						"\twait = %d, completed = %d,\n"
						"\trefcount = %d,\n"
						"\tNext %px\n"
						"\tPrev %px\n}\n",
						cpu, 0,
						node[0].req, node[0].params,
						node[0].status & CC_STAT_LOCK, 
						node[0].status & CC_STAT_DONE,
						node[0].refcount.counter,
						node[0].next,
						node[0].prev
						);
		ld = &per_cpu(lb_info_array, cpu);
		ld->quit = true;

		smp_mb();
		for (j=0; j<INDEX_SIZE; j++) {
			node[j].status = CC_STAT_DONE;
		}
	}
	dummy_lock.counter = 0;
	per_cpu_ptr(node_array, 0)[0].status = 0;

	BUG();
	return 0;
}
#endif
/* module init/exit */
static int lock_benchmark_init(void)
{
	struct cc_node *tmp;
	int cpu;

	lb_debugfs_init();
#ifdef DYNAMIC_PERCPU
	node_array = __alloc_percpu(1<<13, 1<<12);
	for_each_online_cpu(cpu) {
		tmp = per_cpu_ptr(node_array, cpu);
		tmp[0].idx = 1;
	}
#endif
	init_cclock(&dummy_cclock);
	return 0;
}

static void lock_benchmark_exit(void)
{
	int cpu;
	int j;
	struct lb_info *ld;
	struct cc_node *node;

	for_each_online_cpu(cpu) {
		ld = &per_cpu(lb_info_array, cpu);
		ld->quit = true;

		smp_mb();
		node = per_cpu_ptr(node_array, cpu);
		for (j=0; j<INDEX_SIZE; j++) {
			node[j].status = CC_STAT_DONE;
		}
	}
#ifdef DYNAMIC_PERCPU
	if (node_array)
		free_percpu(node_array);
#endif
	lb_debugfs_exit();
	exit_cclock(&dummy_cclock);
}
module_init(lock_benchmark_init);
module_exit(lock_benchmark_exit);
