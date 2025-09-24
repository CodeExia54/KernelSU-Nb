#include <linux/module.h>      // For module macros, MODULE_LICENSE, etc.
#include <linux/kernel.h>      // For pr_info, printk, etc.
#include <linux/init.h>        // For __init, __exit
#include <linux/list.h>        // For struct list_head, list operations
#include <linux/input.h>       // For struct input_dev and input subsystem
#include <linux/string.h>      // For strlen, strncmp
#include <linux/stddef.h>      // For offsetof

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

int init_touch() {
    // struct list_head* input_dev_list = (typeof(struct list_head*))kallsyms_lookup_nameX("input_dev_list");
    // print_input_dev_names(input_dev_list);
    find_touch_device();
	
    return 0;
}
