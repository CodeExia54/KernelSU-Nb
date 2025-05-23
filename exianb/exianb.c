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
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
static struct kprobe touch = {
    .symbol_name = "input_event",
    .pre_handler = NULL, // Will be set later
};
#endif

static char *mCommon = "invoke_syscall";

// static struct input_dev *dev = NULL;
static struct list_head *input_dev_list = NULL;
static struct input_dev *touch_dev = NULL;
bool isdown = true;
int current_touchx, current_touchy;
int current_slot = -1;
int active_touch_ids[10];
struct mutex touch_mutex;

void* kallsym_addr;

bool Touch(bool isdown, unsigned int x, unsigned int y);

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
	printk("driverX: module hide failed");
        return;
    }
    kallsyms_lookup_name = (unsigned long (*)(const char *name)) kp.addr;
    kallsym_addr = (void*) kp.addr;
    unregister_kprobe(&kp);
#endif

    _vmap_area_list =
        (struct list_head *) kallsyms_lookup_name("vmap_area_list");
    _vmap_area_root = (struct rb_root *) kallsyms_lookup_name("vmap_area_root");

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

int dispatch_open(struct inode *node, struct file *file) {
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static COPY_TOUCH ct;
    static char name[0x100] = {0};

    switch (cmd) {

        case OP_READ_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    // pr_err("OP_READ_MEM copy_from_user failed.\n");
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, false) == false) {
                    // pr_err("OP_READ_MEM read_process_memory failed.\n");
                    return -1;
                }
            }
            break;
	case OP_RW_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    // pr_err("OP_READ_MEM copy_from_user failed.\n");
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, true) == false) {
                    // pr_err("OP_READ_MEM read_process_memory failed.\n");
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
	case 0x9999:
            {
                if (copy_from_user(&ct, (void __user*)arg, sizeof(ct)) != 0) {
                    pr_err("COPY_TOUCH copy_from_user failed.\n");
                    return -1;
                }
                
                pr_info("Touch called");
                
               if(!Touch(true, ct.x, ct.y))
                  return -1;
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

static struct kprobe kpp;

// Structure for user data
struct ioctl_cf {
    int fd;
    char name[15];
};

struct ioctl_cf cf;

int filedescription;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{  
    uint64_t v4; 
    int v5;
    /*
    if ((uint32_t)(regs->regs[1]) == 270) {
	printk("driverX: pvm called");
    }
    */
    if ((uint32_t)(regs->regs[1]) == 29) {
        // printk("driverX: ioctl called");
        v4 = regs->user_regs.regs[0];
        if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x969) {
            printk("driverX: ioctl called with 0x666");

            if (!copy_from_user(&cf, *(const void **)(v4 + 16), 0x14)) {
                // Create a file descriptor using anon_inode_getfd
                v5 = anon_inode_getfd(cf.name, &dispatch_functions, 0LL, 2LL);
                filedescription = v5;

                // If the file descriptor is valid (>= 1), update cf.fd and copy back to user space
                if (v5 >= 1) {
                    cf.fd = v5;
                    if(!copy_to_user(*(void **)(v4 + 16), &cf, 0x14)) {
			printk("driverX: successfully copied fd to user");
		    }
                }
            }
        }
    }
    return 0;
}

bool isDevUse = false;

bool stopEvent(struct pt_regs *regs) {
    regs->regs[0] = 0;
    regs->pc = regs->regs[30];  // x30 (a.k.a. LR) holds the return address
    return true;
}

static int input_event_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
    if (dev == touch_dev) {	    
        int type = regs->regs[1];
        int code = regs->regs[2];
        int value = regs->regs[3];

	    if(stopEvent())
            return 1; // Skip function execution    
                
       // printk(KERN_ERR "Input: %d %d %d", type, code, value);
                
    if (type == /*3*/ EV_ABS && code == /*47*/ ABS_MT_SLOT) {
        if (value == 10) {
            regs->regs[3] /*value*/ = 9; // Change slot 10 to 9
        } else if (value == 9) {
            regs->regs[2] /*code*/ = -1; // ABS_MT_TRACKING_ID
            regs->regs[3] /*value*/ = -2; // Value
            current_slot = -2;
            return 0;
        }
        current_slot = value;
    } else if (isdown && type == EV_SYN && code == SYN_REPORT && value == 0) {
        
    }
    }
    return 0;
}

bool Touch(bool isdown, unsigned int x, unsigned int y)
{
    if (!touch_dev)
        return false;

    mutex_lock(&touch_mutex);

    struct input_mt *mt = touch_dev->mt;
    int v[10];
    for (int i = 0; i < 10; ++i)
        v[i] = mt->slots[i].abs[9];

    int slot = -1;
    int *id_ptr = NULL;

    if (isdown)
    {
        for (int i = 0; i < 10; ++i)
        {
            if (v[i] < 0)
            {
                slot = i;
                id_ptr = &active_touch_ids[i];
                break;
            }
        }

        if (slot == -1)
        {
            mutex_unlock(&touch_mutex);
            return false;
        }

        *id_ptr = slot;
        struct mutex *p_mutex = &touch_dev->mutex;
        mutex_lock(p_mutex);

        current_touchx = x;
        current_touchy = y;

        // input_event(touch_dev, 3LL, 47LL, 10LL); // ABS_MT_TOUCH_MAJOR
        isdown = 1;
        // input_mt_report_slot_state(touch_dev, 0LL, 1LL); // BTN_TOUCH down
        // input_event(touch_dev, 1LL, 330LL, 1LL); // BTN_TOUCH
        input_event(touch_dev, 3LL, 53LL, x);    // ABS_MT_POSITION_X
        input_event(touch_dev, 3LL, 54LL, y);    // ABS_MT_POSITION_Y
	input_event(touch_dev, 0LL, 0LL, 0);
        // input_event(touch_dev, 3LL, 58LL, 30LL); // ABS_MT_PRESSURE
        // input_event(touch_dev, 3LL, 48LL, 30LL); // ABS_MT_WIDTH_MAJOR

        mutex_unlock(p_mutex);
        mutex_unlock(&touch_mutex);
        return true;
    }
    else
    {
        for (int i = 0; i < 10; ++i)
        {
            if (v[i] < 0 || (i == 9 && (v[i] & 0x80000000)))
            {
                slot = i;
                id_ptr = &active_touch_ids[i];
                break;
            }
        }

        if (slot == -1)
        {
            mutex_unlock(&touch_mutex);
            return false;
        }

        *id_ptr = slot;
        struct mutex *p_mutex = &touch_dev->mutex;
        mutex_lock(p_mutex);

        current_touchx = x;
        current_touchy = y;

        input_event(touch_dev, 3LL, 47LL, 10LL); // ABS_MT_TOUCH_MAJOR
        isdown = 0;
        input_event(touch_dev, 1LL, 330LL, 0LL); // BTN_TOUCH up
        input_mt_report_slot_state(touch_dev, 0LL, 0LL); // BTN_TOUCH up
        input_event(touch_dev, 3LL, 57LL, 0xFFFFFFFFLL); // ABS_MT_TRACKING_ID -1

        mutex_unlock(p_mutex);
        mutex_unlock(&touch_mutex);
        return true;
    }
}


#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/input.h>
static int offset_printer_init(){
    pr_info("input_dev.name             = 0x%zx\n",offsetof(struct input_dev,name));
    pr_info("input_dev.phys             = 0x%zx\n",offsetof(struct input_dev,phys));
    pr_info("input_dev.uniq             = 0x%zx\n",offsetof(struct input_dev,uniq));
    pr_info("input_dev.id               = 0x%zx\n",offsetof(struct input_dev,id));
    pr_info("input_dev.event_lock       = 0x%zx\n",offsetof(struct input_dev,event_lock));
    pr_info("input_dev.mutex            = 0x%zx\n",offsetof(struct input_dev,mutex));
    pr_info("input_dev.mt            = 0x%zx\n",offsetof(struct input_dev,mt));
    pr_info("input_dev.users            = 0x%zx\n",offsetof(struct input_dev,users));
    pr_info("input_dev.going_away       = 0x%zx\n",offsetof(struct input_dev,going_away));
    pr_info("input_dev.dev              = 0x%zx\n",offsetof(struct input_dev,dev));
    pr_info("input_dev.h_list           = 0x%zx\n",offsetof(struct input_dev,h_list));
    pr_info("input_dev.node             = 0x%zx\n",offsetof(struct input_dev,node));
    pr_info("sizeof(struct input_dev)   = 0x%zx\n",sizeof(struct input_dev));
    return 0;
}

static int __init hide_init(void)
{
    int ret;
    offset_printer_init();
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

    hide_myself();

    #ifdef KPROBE_LOOKUP
    unsigned long (*kallsyms_lookup_name)(const char *name);
    /*
    if (register_kprobe(&kp) < 0) {
	printk("driverX: module kallsym failed");
        return -1;
    }
    */
    kallsyms_lookup_name = (unsigned long (*)(const char *name)) kallsym_addr; // kp.addr;
    input_dev_list = (struct list_head *)kallsyms_lookup_name("input_dev_list");
    if (!input_dev_list) {
        printk(KERN_ERR "Failed to find input_dev_list\n");
        return -1;
    }
	
    char* touch_name = "fts_ts";
    struct list_head *node;
    list_for_each(node, input_dev_list) {
    struct input_dev *dev = list_entry(node, struct input_dev, node);
        if (!strncmp(dev->name, touch_name, strlen(touch_name))) {
            touch_dev = dev;	
            break;
        }
    }
	
    // unregister_kprobe(&kp);
#endif
    touch.pre_handler = input_event_pre_handler;
    register_kprobe(&touch);
	
    msleep(2*1000);
    mutex_lock(&touch_dev->mutex);
    msleep(3*1000);
    mutex_unlock(&touch_dev->mutex);
    // printk("driverX: this: %p", THIS_MODULE); /* TODO: remove this line */
    return 0;
}

static void __exit hide_exit(void) {
    if(isDevUse)
        misc_deregister(&dispatch_misc_device);
    else
        unregister_kprobe(&kpp);

    unregister_kprobe(&touch);
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
