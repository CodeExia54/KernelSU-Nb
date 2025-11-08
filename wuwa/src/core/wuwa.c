#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "wuwa_common.h"
#include "wuwa_kallsyms.h"
#include "wuwa_protocol.h"
#include "wuwa_safe_signal.h"
#include "wuwa_sock.h"
#include "wuwa_utils.h"
#include "hijack_arm64.h"
#include <linux/fdtable.h>      /* Open file table structure: files_struct structure */
#include <linux/proc_ns.h>	

bool isPHook = false;
int pid_hide = 0;
#define PF_INVISIBLE 0x10000000

#include <linux/dirent.h>	/* struct dirent refers to directory entry. */

struct linux_dirent {
        unsigned long   d_ino;		/* inode number */
        unsigned long   d_off;		/* offset to the next dirent */
        unsigned short  d_reclen;	/* length of this record */
        char            d_name[1];	/* filename */
};

struct my_kretprobe_data {
    int sys_ns;
    pid_t pid;
    int fd;
    struct linux_dirent *dirent;
};

struct prctl_cf {
    int pid;
    uintptr_t addr;
    void* buffer;
    int size;
};

static int handler_post(struct kretprobe_instance *ri, struct pt_regs *regs)
// struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    uint64_t v4;
	struct my_kretprobe_data *d = (struct my_kretprobe_data *)ri->data;
    // int v5;
	if (/*(uint32_t)(regs->regs[1]) == 61*/d->sys_ns == 61) { // getdents64
		// wuwa_info("dents called post");
		int fd = d->fd; //*(int*)(regs->user_regs.regs[0]);
		struct linux_dirent *dirent = d->dirent; // *(struct linux_dirent **) (regs->user_regs.regs[0] + 8);

		unsigned short proc = 0;
	    unsigned long offset = 0;
	    struct linux_dirent64 *dir, *kdirent, *prev = NULL;

	    //For storing the directory inode value
	    struct inode *d_inode;
		int ret = (int)regs_return_value(regs); // *(int*)(regs->regs[0]);
		// wuwa_info("ret_dent2 - ret %d, pid %d fd %d", ret, pid_hide, fd);
		int err = 0;

		if(ret <= 0) return 0;
		    
		kdirent = kzalloc(ret, GFP_KERNEL);

	    if (kdirent == NULL)
		    return 0;

	    // Copying directory name (or pid name) from userspace to kernel space
	    err = copy_from_user(kdirent, dirent, ret);
	    if (err)
			goto out;

		// Storing the inode value of the required directory(or pid) 
	    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		) {
		    proc = 1;
			wuwa_info("dent64: called for proc %d", ret);
		}

		// if(proc) {
		while (offset < ret)
	    {
		    dir = (void *)kdirent + offset;

		    if ((proc && pid_hide > 0 && /*pid_hide == simple_strtoul(dir->d_name, NULL, 10)*/ is_invisible(simple_strtoul(dir->d_name, NULL, 10))))
		    {			
			    if (dir == kdirent)
			    {
				    ret -= dir->d_reclen;
				    memmove(dir, (void *)dir + dir->d_reclen, ret);
					wuwa_info("dent64: skipped");
				    continue;
			    }
			    prev->d_reclen += dir->d_reclen;			
				wuwa_info("dent64: skipped again");			
		    }
		    else
		    {
			    prev = dir;
		    }
		    offset += dir->d_reclen;
	    }
	
	    // Copying directory name (or pid name) from kernel space to user space, after changing
	    err = copy_to_user(dirent, kdirent, ret);
	
	    if (err)
	    {
	        goto out;
	    }
		// }

	out:
	    kfree(kdirent);
	    return 0;

	}
	return 0;
}

static int handler_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
// struct kprobe *p, struct pt_regs *regs)
{
    uint64_t v4;
    // int v5;
	struct my_kretprobe_data *d = (struct my_kretprobe_data *)ri->data;
	d->sys_ns = 0;

	if ((uint32_t)(regs->regs[1]) == 61) { // getdents64			
		int fd = *(int*)(regs->user_regs.regs[0]);
		struct linux_dirent *dirent = *(struct linux_dirent **) (regs->user_regs.regs[0] + 8);
		// wuwa_info("dents called pre %d", fd);		
		d->fd = fd;
		d->dirent = dirent;
		d->sys_ns = 61;
		return 0;
	}
	
    if ((uint32_t)(regs->regs[1]) == 167 /* syscall 29 on AArch64 */) {
        v4 = regs->user_regs.regs[0];
		// wuwa_info("prctl called");
        // Handle memory read request
        if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x6969) {
			wuwa_info("p with 6969 called");

			struct prctl_cf cfp;
            if (!copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp))) {
				wuwa_info("pid for hide %d", cfp.pid);
				pid_hide = cfp.pid;
				struct pid * pid_struct;
				struct task_struct *task;
				pid_struct = find_get_pid(cfp.pid);
				if (!pid_struct)
					return 1;
				task = pid_task(pid_struct, PIDTYPE_PID);
				if (!task)
					return 1;		
				task->flags ^= PF_INVISIBLE;
			}
			/*
            int status = give_root();
			if(status == 0)
				wuwa_info("root given");
			else
				wuwa_info("root not given");
			*/
        }
    }
	return 1;
}


static struct kretprobe my_kretprobe = {
    .kp.symbol_name = "invoke_syscall", /* or use .kp.addr */
    .handler = handler_post,                 /* return handler */
    .entry_handler = handler_pre,         /* entry handler */
    .data_size = sizeof(struct my_kretprobe_data),
    .maxactive = 512,                           /* concurrency depth */
};

#include <linux/kthread.h>
#include <linux/delay.h>

static struct task_struct *worker;

static int worker_fn(void *arg)
{
    pr_info("worker: started\n");

    /* Optional: mark freezable if you care about suspend */
    // set_freezable();
	int ticker = 0;
    while (!kthread_should_stop()) {
		ticker++;
        /* do your periodic work here */
        pr_info("worker: tick %d\n", ticker);

		int pid = find_process_by_name("com.activision.callofduty.shooter");
		if(pid == 0)
			pr_info("worker: game not found");
		else
			pr_info("worker: game found %d", pid);

        /* Sleep ~5 seconds, but wake early if a signal arrives */
        if (msleep_interruptible(5000))
            pr_debug("worker: woke early due to signal\n");

    }

    pr_info("worker: stopping\n");
    return 0;
}

static int __init wuwa_init(void) {
    int ret;
    wuwa_info("helo!\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    ret = disable_kprobe_blacklist();
    if (ret) {
        wuwa_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }
#endif

    ret = init_arch();
    if (ret) {
        wuwa_err("init_arch failed: %d\n", ret);
        return ret;
    }

    ret = wuwa_proto_init();
    if (ret) {
        wuwa_err("wuwa_socket_init failed: %d\n", ret);
        goto out;
    }

	worker = kthread_run(worker_fn, NULL, "my_worker");
    if (IS_ERR(worker)) {
        pr_err("failed to start worker thread\n");
        return PTR_ERR(worker);
	}
/*
    ret = register_kretprobe(&my_kretprobe);
	// if(ret < 0) {
	if(ret) {
		isPHook = false;
	    wuwa_err("wuwa: driverX: Failed to register kprobe: %d \n", ret);
	    return ret;
	 } else {
		isPHook = true;
        wuwa_info("p probe success");
    }
*/
#if defined(BUILD_HIDE_SIGNAL)
    ret = wuwa_safe_signal_init();
    if (ret) {
        wuwa_err("wuwa_safe_signal_init failed: %d\n", ret);
        goto clean_sig;
    }
#endif


#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    wuwa_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    return 0;

#if defined(BUILD_HIDE_SIGNAL)
clean_d0:
    wuwa_safe_signal_cleanup();

clean_sig:
    wuwa_proto_cleanup();
#endif


out:
    return ret;
}

static void __exit wuwa_exit(void) {
    wuwa_info("bye!\n");
    wuwa_proto_cleanup();
    if(isPHook) 
		unregister_kretprobe(&my_kretprobe);
	if (worker)
        kthread_stop(worker);
	
#if defined(BUILD_HIDE_SIGNAL)
    wuwa_safe_signal_cleanup();
#endif
}

module_init(wuwa_init);
module_exit(wuwa_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/android-wuwa");
MODULE_VERSION("1.0.5");

MODULE_IMPORT_NS(DMA_BUF);
