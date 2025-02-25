#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/proc_fs.h> 
#include <linux/sched.h> 
#include <linux/uaccess.h> 
#include <linux/version.h> 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) 
#include <linux/minmax.h> 
#endif 
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) 
#define HAVE_PROC_OPS 
#endif 
 
#define PROCFS_MAX_SIZE 2048UL 
#define PROCFS_ENTRY_FILENAME "exianb" 
#define DEVICE_NAME "exianb"
static char *my_string = "exianb";
static struct proc_dir_entry *our_proc_file; 

// static struct miscdevice dispatch_misc_device;
module_param(my_string, charp, 0644); // String parameter
MODULE_PARM_DESC(my_string, "Parameter");

int dispatch_open(struct inode *node, struct file *file) {
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};

    switch (cmd) {
        case OP_READ_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    pr_err("OP_READ_MEM copy_from_user failed.\n");
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    pr_err("OP_READ_MEM read_process_memory failed.\n");
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
                    pr_err("OP_MODULE_BASE copy_from_user failed.\n");
                    return -1;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                    pr_err("OP_MODULE_BASE copy_to_user failed.\n");
                    return -1;
                }
            }
            break;
        default:
            break;
    }
return 0;
}
/*
#ifdef HAVE_PROC_OPS 
static struct proc_ops file_ops_4_our_proc_file = { 
    .proc_ioctl = dispatch_ioctl,
    .proc_open = dispatch_open, 
    .proc_release = dispatch_close, 
}; 
#else 
static const struct file_operations file_ops_4_our_proc_file = { 
    .unlocked_ioctl = dispatch_ioctl,
    .open = dispatch_open, 
    .release = dispatch_close, 
}; 
#endif 
*/

struct file_operations dispatch_functions = {
    .owner   = THIS_MODULE,
    .open    = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dispatch_functions,
};

int __init driver_entry(void) {
    // int ret;
    pr_info("[+] device loaded");
    
    dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
    dispatch_misc_device.name = my_string; // "exianb";
    dispatch_misc_device.fops = &dispatch_functions;
    
    ret = misc_register(&dispatch_misc_device);
    
    return ret;
}

void __exit driver_unload(void) {
    pr_info("[+] device unloaded");    
    misc_deregister(&dispatch_misc_device);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
