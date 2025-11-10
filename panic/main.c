#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include<linux/kmsg_dump.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PWY");
MODULE_DESCRIPTION("A simple kernel module is used to log Linux kernel crashes");
MODULE_VERSION("0.1");

bool is_panic = false;

static struct file *(*filp_open_)(const char *filename, int flags, umode_t mode) = NULL;
static int (*filp_close_)(struct file *filp, fl_owner_t id) = NULL;

static ssize_t (*kernel_write_)(struct file *file, const void *buf, size_t count,
    loff_t *pos) = NULL;

static unsigned long (*kallsyms_lookup_name_fun_)(const char* name) = NULL; 


// kretprobe for dump_backtrace
static __nocfi int ret_handler_dump_backtrace(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    struct file *file;
    struct kmsg_dumper dumper = { };
    size_t len = 0;
    char line[512] = {0};
    ssize_t ret;
    if(is_panic){
        file = filp_open_("/sdcard/Download/panic_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (IS_ERR(file)) {
            pr_err("Failed to open panic_log.txt\n");
            return 0;
        }
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,10,0)
        dumper.active = true;
    
        while (kmsg_dump_get_line(&dumper, false, line, sizeof(line), &len)) {
            ret = kernel_write_(file, line, len, &file->f_pos);
            if(ret != len)
                break;
        }
#else
       struct kmsg_dump_iter iter = {0};
       kmsg_dump_rewind(&iter);
       while (kmsg_dump_get_line(&iter, false, line, sizeof(line), &len)) {
            ret = kernel_write_(file, line, len, &file->f_pos);
            if (ret < 0) {
                pr_err("kernel_write failed: %zd\n", ret);
                break;
            }
        }


#endif
        vfs_fsync(file, 0);
        filp_close_(file, NULL);
    }
    return 0;
}

static struct kretprobe kp_dump_backtrace = {
    .handler = ret_handler_dump_backtrace,
    .maxactive = 20,
    .kp.symbol_name = "dump_backtrace",
};

// kprobe for panic
static int handler_panic(struct kprobe *p, struct pt_regs *regs)
{
    is_panic = true;
    return 0;
}

static struct kprobe kp_panic = {
    .symbol_name = "panic",
    .pre_handler = handler_panic,
};

// kprobe for die
static int handler_die(struct kprobe *p, struct pt_regs *regs)
{
    is_panic = true;
    return 0;
}

static struct kprobe kp_die = {
    .symbol_name = "die",
    .pre_handler = handler_die,
};

static struct kprobe kp_kallsyms = {
    /* data */
    .symbol_name = "kallsyms_lookup_name",
    
};

static int noop(struct kprobe *p,struct pt_regs *regs) { return 0; }



unsigned long find_kallsyms(void)
{
	//return find_func_addr(kp_update_mapping_prot);
	
    int ret=-1;
    unsigned long addr = 0;	
	if(kallsyms_lookup_name_fun_)
        return (uint64_t)kallsyms_lookup_name_fun_;
	
    kp_kallsyms.pre_handler = noop;

    ret = register_kprobe(&kp_kallsyms);

    if(ret < 0)
    {
        return 0;
    }
    addr=(unsigned long)kp_kallsyms.addr;
    kallsyms_lookup_name_fun_ = (void*)addr;
    unregister_kprobe(&kp_kallsyms);
    return addr;
}



static __nocfi int __init panic_store_init(void)
{
    int ret;

    find_kallsyms();

    filp_open_ = (void*)kallsyms_lookup_name_fun_("filp_open");
    filp_close_ = (void*)kallsyms_lookup_name_fun_("filp_close");
    kernel_write_ = (void*)kallsyms_lookup_name_fun_("kernel_write");

    pr_info("[db]filp_open_ : %lx\n", filp_open_);
    pr_info("[db]filp_close_ : %lx\n", filp_close_);
    pr_info("[db]kernel_write_ : %lx\n", kernel_write_);

    ret = register_kretprobe(&kp_dump_backtrace);
    if (ret < 0) {
        pr_err("register_kretprobe failed for dump_backtrace: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&kp_panic);
    if (ret < 0) {
        pr_err("register_kprobe failed for panic: %d\n", ret);
        unregister_kretprobe(&kp_dump_backtrace);
        return ret;
    }

    ret = register_kprobe(&kp_die);
    if (ret < 0) {
        pr_err("register_kprobe failed for die: %d\n", ret);
        unregister_kretprobe(&kp_dump_backtrace);
        unregister_kprobe(&kp_panic);
        return ret;
    }

    pr_info("Kretprobe and Kprobes registered successfully\n");
    memset((void*)0, 0, 100);
    return 0;
}

static void __exit panic_store_exit(void)
{
    unregister_kretprobe(&kp_dump_backtrace);
    unregister_kprobe(&kp_panic);
    unregister_kprobe(&kp_die);
    pr_info("Kretprobe and Kprobes unregistered\n");
}

module_init(panic_store_init);
module_exit(panic_store_exit);
