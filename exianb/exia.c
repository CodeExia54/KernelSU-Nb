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

static struct miscdevice dispatch_misc_device;

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

int dispatch_open(struct inode *node, struct file *file) { return 0; }
int dispatch_close(struct inode *node, struct file *file) { return 0; }

bool isFirst = true;
static struct kprobe kpp;

// Use the same operation codes as defined in comm.h
#define PR_OP_INIT_KEY    OP_INIT_KEY
#define PR_OP_READ_MEM    OP_READ_MEM
#define PR_OP_WRITE_MEM   OP_WRITE_MEM
#define PR_OP_MODULE_BASE OP_MODULE_BASE
#define PR_OP_RW_MEM      OP_RW_MEM

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
        case PR_OP_READ_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, false))
                return -EINVAL;
            break;

        case PR_OP_RW_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, true))
                return -EINVAL;
            break;

        case PR_OP_WRITE_MEM:
            if (copy_from_user(&cm, arg, sizeof(cm)))
                return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
                return -EINVAL;
            break;

        case PR_OP_MODULE_BASE:
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

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
};

struct prctl_cf {
    int fd;
    char name[15];
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    uint64_t v4;
    int v5;
    struct prctl_cf cf;

    if ((uint32_t)(regs->regs[1]) == 167 /* PRCTL */) {
        v4 = regs->user_regs.regs[0];
        if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == PR_OP_INIT_KEY) {
            if (!copy_from_user(&cf, *(const void **)(v4 + 16), sizeof(cf))) {
                v5 = anon_inode_getfd(cf.name, &dispatch_functions, NULL, O_RDWR);
                if (v5 >= 0) {
                    cf.fd = v5;
                    if (copy_to_user(*(void **)(v4 + 16), &cf, sizeof(cf)))
                        close_fd(v5);
                    else
                        pr_info("driverX: successfully copied fd to user");
                }
            }
        }
    }
    return 0;
}

bool isDevUse = false;

static int __init hide_init(void)
{
    int ret;
    kpp.symbol_name = mCommon;
    kpp.pre_handler = handler_pre;

    dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
    dispatch_misc_device.name = "quallcomm_null";
    dispatch_misc_device.fops = &dispatch_functions;
    
    ret = register_kprobe(&kpp);
    if (ret < 0) {
        kpp.symbol_name = "invoke_syscall";
        ret = register_kprobe(&kpp);
        if (ret < 0) {
            isDevUse = true;
            ret = misc_register(&dispatch_misc_device);
            if (ret < 0)
                return ret;
        }
    }
    
    hide_myself();
    return 0;
}

static void __exit hide_exit(void)
{
    if (isDevUse)
        misc_deregister(&dispatch_misc_device);
    else
        unregister_kprobe(&kpp);
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
