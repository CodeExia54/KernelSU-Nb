#include <linux/module.h>      // For module macros, MODULE_LICENSE, etc.
#include <linux/kernel.h>      // For pr_info, printk, etc.
#include <linux/init.h>        // For __init, __exit
#include <linux/list.h>        // For struct list_head, list operations
#include <linux/input.h>       // For struct input_dev and input subsystem
#include <linux/string.h>      // For strlen, strncmp
#include <linux/stddef.h>      // For offsetof

#include <linux/module.h>       // For module macros, MODULE_LICENSE, etc.
#include <linux/kernel.h>       // For printk, pr_info, etc.
#include <linux/init.h>         // For __init, __exit
#include <linux/slab.h>         // For kmalloc, kfree, kvmalloc
#include <linux/vmalloc.h>      // For kvmalloc (internally)
#include <linux/spinlock.h>     // For spinlock_t, spin_lock_init
#include <linux/kprobes.h>      // For kprobes, register/unregister_kprobe
#include <linux/errno.h>        // For error codes like -ENOMEM

static struct event_pool *pool = NULL;
struct input_dev* touch_dev;

struct event_pool * get_event_pool(void) {
	return pool;
}

void print_input_dev_names(struct list_head *input_dev_list) {
    struct list_head *pos;
    struct input_dev *dev;

    // Start from the first node
    pos = input_dev_list->next;
    char* touch_name = "fts_ts";
    int name_size = strlen(touch_name);

    // Traverse the list until we return to the head
    while (pos != input_dev_list) {
        // Get the input_dev structure from the list_head
        dev = (struct input_dev *)((char *)pos - offsetof(struct input_dev, node));
        
        // Print the device name
        pr_info("pvm: Device Name: %s\n", dev->name);
        if ( !strncmp((const char *)dev->name, touch_name, name_size) ) {
            pr_info("------> pvm: Device asigned %s", dev->name);
            touch_dev = dev;            
        }

        // Move to the next node
        pos = pos->next;
    }
}

struct input_dev* find_touch_device(void) {
	static struct input_dev* CACHE = NULL;

	if (CACHE != NULL) {
		return CACHE;
	}

	struct input_dev *dev;
	struct list_head *input_dev_list;
	struct mutex *input_mutex;

	input_dev_list = (struct list_head *)kallsyms_lookup_nameX("input_dev_list");
	input_mutex = (struct mutex *)kallsyms_lookup_nameX("input_mutex");
	if (!input_dev_list || !input_mutex) {
		printk(KERN_ERR "Failed to find symbols!\n");
		return NULL;
	}

	// /*
	// * input_mutex protects access to both input_dev_list and input_handler_list.
	// * This also causes input_[un]register_device and input_[un]register_handler
	// * be mutually exclusive which simplifies locking in drivers implementing
	// * input handlers.
	// */
	//static DEFINE_MUTEX(input_mutex);
	mutex_lock(input_mutex);

	list_for_each_entry(dev, input_dev_list, node) {
		if (test_bit(EV_ABS, dev->evbit) &&
			(test_bit(ABS_MT_POSITION_X, dev->absbit) || test_bit(ABS_X, dev->absbit))) {\
            pr_info("[pvm] Name: %s, Bus: %d Vendor: %d Product: %d Version: %d\n",
					dev->name,
					dev->id.bustype, dev->id.vendor,
					dev->id.product, dev->id.version);
			mutex_unlock(input_mutex);
			CACHE = dev;
			return dev;
		}
	}

	mutex_unlock(input_mutex);
	return NULL;
}

struct TouchContact {
        int posX;
        int posY;
        int mt_slot_id;
        int mt_tracking_id;
        int mt_pressure;
        int uniqueID;
        int mt_touch_major;
        bool enabled;
};

struct TouchContact contacts[20];

bool is_mt_down = false;
bool isPressure = false;
bool isBtnDown = false;
int currSlot = 0;

static int input_handle_event_handler_pre(struct kprobe *p,
										  struct pt_regs *regs)
{
	unsigned int type = (unsigned int)regs->regs[1];
	unsigned int code = (unsigned int)regs->regs[2];
	int value = (int)regs->regs[3];

	struct input_dev* dev = (struct input_dev*)regs->regs[0];
	if(!dev) {
		return 0;
	}

	switch (type) {
		case EV_SYN:
			if(code == SYN_REPORT){
                // hasSyn = true;
                // TS printf("SYN_REPORT\n");
			}
            break;
        case EV_KEY:
            if (code == BTN_TOUCH) {
                // TS printf("BTN_TOUCH: %s\n", (evt.value == 1) ? "DOWN" : "UP");
            }
            break;
		case EV_ABS:
            switch (code) {
                case ABS_MT_SLOT:
                    currSlot = value;
                    //if(currSlot == 9)
                    //    isRunning = false;
                    contacts[currSlot].mt_slot_id = value;
                    // TS printf("ABS_MT_SLOT: %d\n", evt.value);
                    break;
				case ABS_MT_TRACKING_ID:
                    contacts[currSlot].enabled = value != -1;
                    if(value != -1)
                        contacts[currSlot].mt_tracking_id = 10+currSlot; //value;
                    else
                        contacts[currSlot].mt_tracking_id = -1;
                                
                    if(value != -1) { 
                        contacts[currSlot].uniqueID = value;
                        //  allocate_slot(value, currSlot);
                    }
                    // TS printf("ABS_MT_TRACKING_ID: %d | Slot: %d\n", evt.value, currSlot);
                    break;
				case ABS_MT_TOUCH_MAJOR:
                    contacts[currSlot].mt_touch_major = value;
                    // TS printf("ABS_MT_TOUCH_MAJOR: %d | Slot: %d\n", evt.value, currSlot);
                    break;
                case ABS_MT_PRESSURE:
                    contacts[currSlot].mt_pressure = value;
                    isPressure = true;
                    // TS printf("ABS_MT_PRESSURE: %d | Slot: %d\n", evt.value, currSlot);
                    break;
                case ABS_MT_POSITION_X:
                    contacts[currSlot].posX = value;
                    // TS printf("ABS_MT_POSITION_X: %d | Slot: %d\n", evt.value, currSlot);
                    break;
                case ABS_MT_POSITION_Y:
                    contacts[currSlot].posY = value;
                    // TS printf("ABS_MT_POSITION_Y: %d | Slot: %d\n", evt.value, currSlot);
                    break;
			}
		    break;
	}

	if (type != EV_SYN) {
		return 0;
	}

	// handle_cache_events(dev);
	return 0;
}

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

int init_touch() {
    // struct list_head* input_dev_list = (typeof(struct list_head*))kallsyms_lookup_nameX("input_dev_list");
    // print_input_dev_names(input_dev_list);
    touch_dev = find_touch_device();

    ret = register_kprobe(&input_event_kp);
	pr_info("[pvm] input_event_kp: %d\n", ret);
	if (ret) {
		return ret;
	}
	
	pool = kvmalloc(sizeof(struct event_pool), GFP_KERNEL);
	if (!pool) {
		unregister_kprobe(&input_event_kp);
//		unregister_kprobe(&input_inject_event_kp);
//		unregister_kprobe(&input_mt_sync_frame_kp);
		return -ENOMEM;
	}
	pool->size = 0;
	spin_lock_init(&pool->event_lock);
	
    return 0;
}

void exit_touch(void) {
	unregister_kprobe(&input_event_kp);
//	unregister_kprobe(&input_inject_event_kp);
//	unregister_kprobe(&input_mt_sync_frame_kp);
	if (pool)
		kfree(pool);
}
