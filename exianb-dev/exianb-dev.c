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

    }

    return 0;
}

bool isDevUse = false;

static int __init hide_init(void)
{
    // int ret;

	// hide_myself();
    
    // printk("driverX: this: %p", THIS_MODULE); /* TODO: remove this line */
    return 0;
}

static void __exit hide_exit(void) {
	/*
    if(isDevUse)
        misc_deregister(&dispatch_misc_device);
    else
        unregister_kprobe(&kpp);
	*/
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");
MODULE_VERSION("2.0");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
