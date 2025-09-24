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

void init_touch() {
    struct list_head* input_dev_list = (typeof(struct list_head*))kallsyms_lookup_name("input_dev_list");
    print_input_dev_names(input_dev_list);
}
