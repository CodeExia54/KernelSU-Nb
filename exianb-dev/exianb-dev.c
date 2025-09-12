#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#include <linux/kernel.h> 
#include <linux/proc_fs.h> 
#include <linux/sched.h> 
#include <linux/uaccess.h> 
#include <linux/version.h> 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) 
#include <linux/minmax.h> 
#endif 
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>
#include "server.h"

// bool isDevUse = false;

static int __init pvm_init(void)
{


	int ret;

    ret = init_server();
    if (ret) {
        pr_err("pvm: failed to initialize server: %d\n", ret);
        return ret;
	}

	struct task_struct *task;

    // Pick the first process in the task list (usually init)
    task = &init_task;

    unsigned long base     = (unsigned long)task;
    unsigned long off_mm   = (unsigned long)&task->mm   - base;
    unsigned long off_comm = (unsigned long)&task->comm - base;
	unsigned long off_pid = (unsigned long)&task->pid - base;
	
    // pr_info("init_task: pid=%d comm=%s\n", task_pid_nr(task), task->comm);
    pr_info("Offsets relative to task_struct: mm=%lu, comm=%lu pid=%lu\n",
            off_mm, off_comm, off_pid);
    // int ret;
	// hide_myself();
    // printk("driverX: this: %p", THIS_MODULE); /* TODO: remove this line */
    return 0;
}

static void __exit pvm_exit(void) {
	/*
    if(isDevUse)
        misc_deregister(&dispatch_misc_device);
    else
        unregister_kprobe(&kpp);
	*/
	exit_server();
}

module_init(pvm_init);
module_exit(pvm_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");
MODULE_VERSION("2.0");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
