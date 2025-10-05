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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
#endif

static char *mCommon = "invoke_syscall";

module_param(mCommon, charp, 0644);
MODULE_PARM_DESC(mCommon, "Parameter");

static struct miscdevice dispatch_misc_device;

unsigned long (*kallsyms_lookup_nameX)(const char *name);

static void __init hide_myself(void)
{
    struct vmap_area *va, *vtmp;
    struct module_use *use, *tmp;
    struct list_head *_vmap_area_list;
    struct rb_root *_vmap_area_root;

#ifdef KPROBE_LOOKUP
    
    if (register_kprobe(&kp) < 0) {
	    printk("driverX: module hide failed");
        return;
    }
    kallsyms_lookup_nameX = (unsigned long (*)(const char *name)) kp.addr;
    unregister_kprobe(&kp);
#endif
	
   return;
	
    _vmap_area_list =
        (struct list_head *) kallsyms_lookup_nameX("vmap_area_list");
    _vmap_area_root = (struct rb_root *) kallsyms_lookup_nameX("vmap_area_root");

    /* hidden from /proc/vmallocinfo */
    list_for_each_entry_safe (va, vtmp, _vmap_area_list, list) {
        if ((unsigned long) THIS_MODULE > va->va_start &&
            (unsigned long) THIS_MODULE < va->va_end) {
            list_del(&va->list);
            /* remove from red-black tree */
            rb_erase(&va->rb_node, _vmap_area_root);
        }
    }

    /* hidden from /proc/modules */
    list_del_init(&THIS_MODULE->list);

    /* hidden from /sys/modules */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    /* decouple the dependency */
    list_for_each_entry_safe (use, tmp, &THIS_MODULE->target_list,
                              target_list) {
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
    }
}

/* global storage for the pointer */
static int (*my_get_cmdline)(struct task_struct *tsk,
                             char *buf, int buflen);
           /* ← hard-coded address */

/* unchanged logic below … */
pid_t find_process_by_name(const char *name) {
    struct task_struct *task;
    char cmdline[256];
    size_t name_len;
    int ret;

    name_len = strlen(name);
	if (name_len == 0) {
        pr_err("[pvm] process name is empty\n");
        return -2;
    }
/*
	#ifdef KPROBE_LOOKUP  
    if (register_kprobe(&kp) < 0) {
	    printk("pvm: driverX: module hide failed");
        return 0;
    }
    kallsyms_lookup_nameX = (unsigned long (*)(const char *name)) kp.addr;
    unregister_kprobe(&kp);
    #endif
*/
	bool is6_1up = false;
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	is6_1up = true;
	#endif

	if(is6_1up) 
		pr_info("pvm: getpid up 6.1 kernel used for cmdline");
	else
		pr_info("pvm: getpid below 6.1  kernel used for task threads");
    
    if (my_get_cmdline == NULL && is6_1up) {
        my_get_cmdline = (void *) kallsyms_lookup_nameX("get_cmdline");
        // It can be NULL, because there is a fix below if get_cmdline is NULL
    }
    
 // code from https://github.com/torvalds/linux/blob/master/kernel/sched/debug.c#L797
    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL && is6_1up) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
			// ret = -1;
        } else {
            ret = -1;
        }

        if (ret < 0) {
            // Fallback to task->comm
            printk("[pvm] using task->comm for pid %d : %s\n", task->pid, task->comm);
            if (strncmp(task->comm, name, min(strlen(task->comm), name_len)) == 0) {
                rcu_read_unlock();
                pr_info("[pvm] pid matched returning %d", task->pid);
                return task->pid;
            }
        } else {
            printk("[pvm] success to get cmdline for pid %d : %s\n", task->pid, cmdline);
            if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0) {
                pr_info("[pvm] (in cmdline) pid matched returning %d", task->pid);
                rcu_read_unlock();
                return task->pid;
            }
        }
    }

    rcu_read_unlock();
    return -69;
}

int dispatch_open(struct inode *node, struct file *file) {
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

bool isFirst = true;
static struct kprobe kpp;

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};

    if(isFirst) {
	 //   unregister_kprobe(&kpp);
	    isFirst = false;
    }

    switch (cmd) {
        case OP_READ_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    pr_err("pvm: OP_READ_MEM copy_from_user failed.\n");
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, false) == false) {
                    pr_err("pvm: OP_READ_MEM read_process_memory failed.\n");
                    return -1;
                }
            }
            break;
	case OP_RW_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    pr_err("pvm: OP_READ_MEM copy_from_user failed.\n");
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, true) == false) {
                    pr_err("pvm: OP_READ_MEM read_process_memory failed.\n");
                    return -1;
                }
            }
            break;
        case OP_WRITE_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return -1;
                }
                if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return -1;
                }
            }
            break;
        case OP_MODULE_BASE:
            {
                if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
                ||  copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                    // pr_err("OP_MODULE_BASE copy_from_user failed.\n");
                    return -1;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                    // pr_err("OP_MODULE_BASE copy_to_user failed.\n");
                    return -1;
                }
            }
            break;
        default:
            break;
    }
return 0;
}

struct file_operations dispatch_functions = {
    .owner   = THIS_MODULE,
    .open    = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

// Structure for user data
struct ioctl_cf {
    int fd;
    char name[15];
};

struct ioctl_cf cf;

struct prctl_cf {
    int pid;
    uintptr_t addr;
    void* buffer;
    int size;
};

struct prctl_mb {
    pid_t pid;
    char* name;
    uintptr_t base;
};

int filedescription;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    uint64_t v4;
    // int v5;

    if ((uint32_t)(regs->regs[1]) == 167 /* syscall 29 on AArch64 */) {
        v4 = regs->user_regs.regs[0];

        // Handle memory read request
        if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x999) {
            struct prctl_cf cfp;
			// pid_t pidd = find_process_by_name("com.activision.callofduty.shooter");
	        // pr_info("pvm: bgmi pid %d", pidd);
            if (!copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp))) {
                // pr_info("pvm: read request: pid=%d addr=0x%lx size=%d buf=0x%px\n", cfp.pid, cfp.addr, cfp.size, cfp.buffer);
                if (read_process_memory(cfp.pid, cfp.addr, cfp.buffer, cfp.size, false)) {
		
                } else {
                   pr_err("pvm: read_process_memory failed\n");
                }
            }
        }

	if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x9999) {
            struct prctl_cf cfp;
            if (!copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp))) {
                // pr_info("pvm: read request: pid=%d addr=0x%lx size=%d buf=0x%px\n", cfp.pid, cfp.addr, cfp.size, cfp.buffer);
                if (read_process_memory(cfp.pid, cfp.addr, cfp.buffer, cfp.size, true)) {
		
                } else {
                   pr_err("pvm: read_process_memory failed\n");
                }
            }
	} 

    if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x1111) {
        struct prctl_mb cfp;
		static char name[0x100] = {0};
		if (copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp)) != 0 
        ||  copy_from_user(name, (void __user*)cfp.name, sizeof(name)-1) !=0) {
            pr_err("OP_MODULE_BASE copy_from_user failed.\n");
            return -1;
        }
        cfp.base = get_module_base(cfp.pid, name);
		if (copy_to_user(*(void **)(v4 + 16), &cfp, sizeof(cfp)) !=0) {
            pr_err("OP_MODULE_BASE copy_to_user failed.\n");
            return -1;
		}
	}

    if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x2222) {
        struct prctl_mb cfp;
		static char name[0x100] = {0};
		if (copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp)) != 0 
        ||  copy_from_user(name, (void __user*)cfp.name, sizeof(name)-1) !=0) {
            pr_err("OP_MODULE_PID copy_from_user failed.\n");
            return -1;
        }
        cfp.pid = find_process_by_name(name);
		if (copy_to_user(*(void **)(v4 + 16), &cfp, sizeof(cfp)) !=0) {
            pr_err("OP_MODULE_PID copy_to_user failed.\n");
            return -1;
		}
	}
		
    }

    return 0;
}

bool isDevUse = false;

static int __init hide_init(void)
{
    int ret;
    // kpp.symbol_name = "el0_svc_common";
    kpp.symbol_name = mCommon; // "invoke_syscall";
    kpp.pre_handler = handler_pre;

    dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
    dispatch_misc_device.name = "quallcomm_null";
    dispatch_misc_device.fops = &dispatch_functions;
    
    ret = register_kprobe(&kpp);
    if (ret < 0) {	
        pr_err("driverX: Failed to register kprobe: %d (%s)\n", ret, kpp.symbol_name);

	    kpp.symbol_name = "invoke_syscall";
        kpp.pre_handler = handler_pre;  

	    ret = register_kprobe(&kpp);
	    if(ret < 0) {
	        isDevUse = true;
	        ret = misc_register(&dispatch_misc_device);
	        pr_err("driverX: Failed to register kprobe: %d (%s) using dev\n", ret, kpp.symbol_name);
	        return ret;
	    }       
    }

	printk(KERN_INFO "pvm: sizeof(struct input_dev) = %zu\n", sizeof(struct input_dev));
    printk(KERN_INFO "pvm: offset: event_lock = %zu\n", offsetof(struct input_dev, event_lock));
    printk(KERN_INFO "pvm: offset: mt = %zu\n", offsetof(struct input_dev, mt));   // change 'mt' if your kernel uses mt_slots or mt_state
    return 0;

	hide_myself();

    // printk("driverX: this: %p", THIS_MODULE); /* TODO: remove this line */
    return 0;
}

static void __exit hide_exit(void) {
    if(isDevUse)
        misc_deregister(&dispatch_misc_device);
    else
        unregister_kprobe(&kpp);
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");
// MODULE_VERSION("1.0");

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("National Cheng Kung University, Taiwan");
// MODULE_DESCRIPTION("Catch Me If You Can");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
