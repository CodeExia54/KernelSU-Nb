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
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
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
static spinlock_t global_slot_lock = __SPIN_LOCK_UNLOCKED(global_slot_lock);
static char *mCommon = "invoke_syscall";

// static struct input_dev *dev = NULL;
static struct list_head *input_dev_list = NULL;
static struct input_dev *touch_dev = NULL;
bool isdown = true;
int current_touchx, current_touchy;
int current_slot = -1;
//int active_touch_ids[20];
static DEFINE_MUTEX(touch_mutex);

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
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
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
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
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
                
                    pr_info("Touch called, isdown=%d\n", ct.isdown);
                if (!Touch(ct.isdown, ct.x, ct.y))
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



#define MAX_SLOTS 20

/* Remapping table for hardware slots → real slots */
static int hw2remap[MAX_SLOTS];

/* Per-CPU flags for synthetic injection */
static DEFINE_PER_CPU(int, synthetic_active);
static DEFINE_PER_CPU(int, synthetic_slot);
static bool synthetic_pressed = false;
static DEFINE_PER_CPU(int, last_hw_slot);
/* Real touch device pointer (found via kallsyms) */


/* Guards multiple concurrent Touch() callers */


/* Track active touch IDs (not the same as slot number) */
static int active_touch_ids[MAX_SLOTS];

/* Last‐seen synthetic slot & coordinates */

//static unsigned int current_touchx = 0;
//static unsigned int current_touchy = 0;

static int find_free_slot(struct input_dev *dev)
{
    struct input_mt *mt = dev->mt;
    int i;
    /* Compute the index into slots[].abs[] for the tracking ID */
    int tracking_id_idx = ABS_MT_TRACKING_ID - ABS_MT_FIRST;
    for (i = 0; i < mt->num_slots; i++)
        if (mt->slots[i].abs[tracking_id_idx] < 0)
            return i;
    return -1;
}

/* per-CPU store of the most recent raw slot index */

/* sits at top of the file */


static int input_event_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct input_dev *dev   = (struct input_dev *)regs->regs[0];
    int              type  = regs->regs[1];
    int              code  = regs->regs[2];
    int              value = regs->regs[3];
    unsigned long    flags;

    pr_debug("pre_handler: dev=%p type=%d code=%d val=%d\n",
             dev, type, code, value);

    spin_lock_irqsave(&global_slot_lock, flags);

    if (dev == touch_dev) {
        if (type == EV_ABS && code == ABS_MT_SLOT) {
            int orig = value;
            this_cpu_write(last_hw_slot, orig);
            pr_debug("  SLOT event: orig=%d current_slot=%d active=%d pressed=%d\n",
                     orig,
                     this_cpu_read(synthetic_slot),
                     this_cpu_read(synthetic_active),
                     synthetic_pressed);

            /* A) hardware colliding with synthetic_pressed */
            if (!this_cpu_read(synthetic_active) &&
                 synthetic_pressed &&
                 orig == current_slot) {
                int r = find_free_slot(dev);
                if (r >= 0) {
                    hw2remap[orig] = r;
                    regs->regs[3]   = r;
                    pr_info("  remap collision: hw orig=%d → %d (synthetic held)\n",
                            orig, r);
                }
            }
            /* B) during injection, maintain synthetic remap */
            else if (this_cpu_read(synthetic_active) &&
                     orig == this_cpu_read(synthetic_slot)) {
                int r = this_cpu_read(synthetic_slot);
                hw2remap[orig] = r;
                regs->regs[3]   = r;
                pr_info("  remap synthetic: orig=%d → %d\n", orig, r);
            }
            /* C) previously mapped hardware finger */
            else if (orig >= 0 && orig < MAX_SLOTS &&
                     hw2remap[orig] >= 0) {
                int m = hw2remap[orig];
                regs->regs[3] = m;
                pr_debug("  apply existing remap: orig=%d → %d\n", orig, m);
            }

        } else if (type == EV_ABS && code == ABS_MT_TRACKING_ID) {
            int orig   = this_cpu_read(last_hw_slot);
            int mapped = (orig>=0 && orig<MAX_SLOTS) ? hw2remap[orig] : -1;
            pr_debug("  TRACKING_ID event: orig=%d val=%d mapped=%d active=%d\n",
                     orig, value, mapped, this_cpu_read(synthetic_active));

            if (!this_cpu_read(synthetic_active)) {
                /* hardware down/up */
                if (value >= 0 && mapped >= 0) {
                    regs->regs[3] = mapped;
                    pr_info("  hw DOWN: orig=%d → mapped=%d\n", orig, mapped);
                } else if (value < 0 && mapped >= 0) {
                    regs->regs[3] = -1;
                    hw2remap[orig] = -1;
                    pr_info("  hw UP: orig=%d, cleared mapping\n", orig);
                }
            } else {
                /* synthetic down/up */
                if (value >= 0) {
                    synthetic_pressed = true;
                    current_slot      = this_cpu_read(synthetic_slot);
                    pr_info("  synth DOWN: slot=%d\n", current_slot);
                } else {
                    synthetic_pressed = false;
                    current_slot      = -1;
                    pr_info("  synth UP\n");
                }
            }

        } else if (type == EV_ABS &&
                  (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y)) {
            int orig   = this_cpu_read(last_hw_slot);
            int mapped = (orig>=0 && orig<MAX_SLOTS) ? hw2remap[orig] : -1;

            /* drop hardware X/Y until mapped */
            if (!this_cpu_read(synthetic_active) && mapped < 0) {
                pr_warn("  drop POS code=%d orig=%d (unmapped)\n", code, orig);
                spin_unlock_irqrestore(&global_slot_lock, flags);
                return 0;
            }
            /* synthetic X/Y always pass */
            pr_debug("  pass POS code=%d orig=%d mapped=%d\n", code, orig, mapped);
        }
    }

    spin_unlock_irqrestore(&global_slot_lock, flags);
    return 0;
}

/*
bool Touch(bool isdown, unsigned int x, unsigned int y)
{
    struct input_mt *mt;
    int v10;
    int v11;
    int v12;
    int v13;
    int v14;
    int v15;
    int v16;
    int v17;
    int v18;
    int v19;
    int v20;
    int *v21;
    struct mutex *p_mutex;
    long v26;
    long v27;

    if (!touch_dev)
        return false;
    mutex_lock(&touch_mutex);
    mt = touch_dev->mt;
    v10 = mt->slots[0].abs[9];
    v11 = mt->slots[1].abs[9];
    v12 = mt->slots[2].abs[9];
    v13 = mt->slots[3].abs[9];
    v14 = mt->slots[4].abs[9];
    v15 = mt->slots[5].abs[9];
    v16 = mt->slots[6].abs[9];
    v17 = mt->slots[7].abs[9];
    v18 = mt->slots[8].abs[9];
    v19 = mt->slots[9].abs[9];
    if (isdown) {
        if (v10 < 0) { v20 = 0; v21 = &active_touch_ids[0]; goto LABEL_42; }
        if (v11 < 0) { v20 = 1; v21 = &active_touch_ids[1]; goto LABEL_42; }
        if (v12 < 0) { v20 = 2; v21 = &active_touch_ids[2]; goto LABEL_42; }
        if (v13 < 0) { v20 = 3; v21 = &active_touch_ids[3]; goto LABEL_42; }
        if (v14 < 0) { v20 = 4; v21 = &active_touch_ids[4]; goto LABEL_42; }
        if (v15 < 0) { v20 = 5; v21 = &active_touch_ids[5]; goto LABEL_42; }
        if (v16 < 0) { v20 = 6; v21 = &active_touch_ids[6]; goto LABEL_42; }
        if (v17 < 0) { v20 = 7; v21 = &active_touch_ids[7]; goto LABEL_42; }
        if (v18 < 0) { v20 = 8; v21 = &active_touch_ids[8]; goto LABEL_42; }
        if (v19 < 0) { v20 = 9; v21 = &active_touch_ids[9]; goto LABEL_42; }
        mutex_unlock(&touch_mutex);
        return false;
LABEL_42:
        p_mutex = &touch_dev->mutex;
        mutex_lock(p_mutex);
        *v21 = v20;
        current_touchx = x;
        current_touchy = y;
        input_event(touch_dev, 3LL, 47LL, 10LL);
        input_mt_report_slot_state(touch_dev, 0LL, 1LL);
        input_event(touch_dev, 1LL, 330LL, 1LL);
        input_event(touch_dev, 3LL, 53LL, x);
        input_event(touch_dev, 3LL, 54LL, y);
        input_event(touch_dev, 3LL, 58LL, 30LL);
        v26 = 48LL;
        v27 = 30LL;
        input_event(touch_dev, 3LL, v26, v27);
        mutex_unlock(p_mutex);
        mutex_unlock(&touch_mutex);
        return true;
    }
    mutex_unlock(&touch_mutex);
    return false;
}
*/
/*
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

        input_event(touch_dev, 3LL, 47LL, 10LL); // ABS_MT_TOUCH_MAJOR
        isdown = 1;
        input_mt_report_slot_state(touch_dev, 0LL, 1LL); // BTN_TOUCH down
        input_event(touch_dev, 1LL, 330LL, 1LL); // BTN_TOUCH
        input_event(touch_dev, 3LL, 53LL, x);    // ABS_MT_POSITION_X
        input_event(touch_dev, 3LL, 54LL, y);    // ABS_MT_POSITION_Y
        input_event(touch_dev, 3LL, 58LL, 30LL); // ABS_MT_PRESSURE
        input_event(touch_dev, 3LL, 48LL, 30LL); // ABS_MT_WIDTH_MAJOR

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
*/




bool Touch(bool isdown, unsigned int x, unsigned int y)
{
    int slot;
    unsigned long flags;

    if (!touch_dev) {
        pr_err("Touch: no touch_dev\n");
        return false;
    }

    pr_debug("Touch: isdown=%d x=%u y=%u current_slot=%d\n",
             isdown, x, y, current_slot);

    mutex_lock(&touch_mutex);

    if (isdown) {
        /* First down: allocate a slot and send down events */
        if (current_slot < 0) {
            slot = find_free_slot(touch_dev);
            if (slot < 0) {
                pr_warn("Touch: no free slot\n");
                mutex_unlock(&touch_mutex);
                return false;
            }
            current_slot = slot;
            pr_info("Touch: allocated synthetic slot %d\n", slot);

            preempt_disable();
            local_irq_save(flags);
            this_cpu_write(synthetic_slot,   slot);
            this_cpu_write(synthetic_active, 1);
            pr_debug("Touch: inject DOWN slot=%d\n", slot);
            input_event(touch_dev, EV_ABS, ABS_MT_SLOT,        slot);
            input_event(touch_dev, EV_ABS, ABS_MT_TRACKING_ID, slot);
            input_event(touch_dev, EV_SYN, SYN_REPORT,         0);
            local_irq_restore(flags);
            preempt_enable();
        }

        /* Position updates once slot is active */
        preempt_disable();
        local_irq_save(flags);
        this_cpu_write(synthetic_active, 1);
        pr_debug("Touch: inject POS slot=%d x=%u y=%u\n",
                 current_slot, x, y);
        input_event(touch_dev, EV_ABS, ABS_MT_SLOT,       current_slot);
        input_event(touch_dev, EV_ABS, ABS_MT_POSITION_X, x);
        input_event(touch_dev, EV_ABS, ABS_MT_POSITION_Y, y);
        input_event(touch_dev, EV_SYN, SYN_REPORT,        0);
        this_cpu_write(synthetic_active, 0);
        local_irq_restore(flags);
        preempt_enable();

    } else {
        /* Up: only if a slot is active */
        if (current_slot < 0) {
            pr_warn("Touch: up called but no active slot\n");
            mutex_unlock(&touch_mutex);
            return false;
        }

        preempt_disable();
        local_irq_save(flags);
        this_cpu_write(synthetic_active, 1);
        pr_info("Touch: inject UP slot=%d\n", current_slot);
        input_event(touch_dev, EV_ABS, ABS_MT_SLOT,        current_slot);
        input_event(touch_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        input_event(touch_dev, EV_SYN, SYN_REPORT,         0);
        this_cpu_write(synthetic_active, 0);
        local_irq_restore(flags);
        preempt_enable();

        /* Mark slot free for next down */
        pr_debug("Touch: released slot %d\n", current_slot);
        current_slot = -1;
    }

    mutex_unlock(&touch_mutex);
    return true;
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
    int i, ret;
offset_printer_init();
for (i = 0; i < MAX_SLOTS; i++)
    hw2remap[i] = -1;
for (i = 0; i < 10; ++i) 
    active_touch_ids[i] = -1;
    // kpp.symbol_name = "el0_svc_common";
    kpp.symbol_name = mCommon; // "invoke_syscall";
    kpp.pre_handler = handler_pre;

    dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
    dispatch_misc_device.name  = "quallcomm_null";
    dispatch_misc_device.fops  = &dispatch_functions;

    /* try primary kpp probe */
    ret = register_kprobe(&kpp);
    if (ret < 0) {
        pr_err("driverX: Failed to register kpp(%s): %d\n", kpp.symbol_name, ret);

        /* retry on fallback symbol */
        kpp.symbol_name = "invoke_syscall";
        kpp.pre_handler  = handler_pre;
        ret = register_kprobe(&kpp);
        if (ret < 0) {
            pr_err("driverX: Failed to register kpp(invoke_syscall): %d\n", ret);

            /* fallback to misc device */
            isDevUse = true;
            ret = misc_register(&dispatch_misc_device);
            if (ret < 0)
                return ret;
            goto skip_touch_probe;
        }
    }

skip_touch_probe:
    hide_myself();

#ifdef KPROBE_LOOKUP
    unsigned long (*kallsyms_lookup_name)(const char *name);
    kallsyms_lookup_name = (unsigned long (*)(const char *))kallsym_addr;
    input_dev_list = (struct list_head *)kallsyms_lookup_name("input_dev_list");
    if (!input_dev_list)
        return -1;

    char *touch_name = "fts_ts";
    struct list_head *node;
    list_for_each(node, input_dev_list) {
        struct input_dev *dev = list_entry(node, struct input_dev, node);
        if (!strncmp(dev->name, touch_name, strlen(touch_name))) {
            touch_dev = dev;
            break;
        }
    }
#endif

    /* now register the touch-slot kprobe with error check */
    touch.symbol_name = "input_event";
    touch.pre_handler  = input_event_pre_handler;
    ret = register_kprobe(&touch);
    if (ret < 0) {
        pr_err("driverX: Failed to register touch probe: %d\n", ret);
        if (!isDevUse)
            unregister_kprobe(&kpp);
        return ret;
    }

    msleep(2 * 1000);
    mutex_lock(&touch_dev->mutex);
    msleep(3 * 1000);
    mutex_unlock(&touch_dev->mutex);
    return 0;
}

static void __exit hide_exit(void)
{
    if (isDevUse) {
        misc_deregister(&dispatch_misc_device);
    } else {
        unregister_kprobe(&touch);
        unregister_kprobe(&kpp);
    }
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
