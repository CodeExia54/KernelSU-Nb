// print_offsets.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/stddef.h>   /* offsetof */
#include <linux/mm.h>       /* struct mm_struct, struct vm_area_struct */
#include <linux/fs.h>       /* struct file */
#include <linux/dcache.h>   /* struct dentry */
#include <linux/path.h>     /* struct path */
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/sched.h>    /* struct task_struct */
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("offset-printer");
MODULE_DESCRIPTION("Print offsets for mm/vma/file/dentry fields");

static int __init offsets_init(void)
{
    pr_info("offsets: sizeof(void*)=%zu, sizeof(unsigned long)=%zu\n",
            sizeof(void *), sizeof(unsigned long));

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
    /* mm_struct -> mmap */
    pr_info("offsets: offsetof(mm_struct, mmap) = %zu\n",
            offsetof(struct mm_struct, mmap));

    pr_info("offsets: offsetof(mm_struct, mmap_lock) = %zu\n",
            offsetof(struct mm_struct, mmap_lock));

    /* vm_area_struct fields */
    pr_info("offsets: offsetof(vm_area_struct, vm_next) = %zu\n",
            offsetof(struct vm_area_struct, vm_next));

    #endif

    #if (LINUX_VERSION_CODE > KERNEL_VERSION(6, 1, 0))

    pr_info("offsets: offsetof(mm_struct, mm_mt) = %zu\n",
            offsetof(struct mm_struct, mm_mt));
    #endif
    
    
    pr_info("offsets: offsetof(vm_area_struct, vm_start) = %zu\n",
            offsetof(struct vm_area_struct, vm_start));
    pr_info("offsets: offsetof(vm_area_struct, vm_file)  = %zu\n",
            offsetof(struct vm_area_struct, vm_file));
    pr_info("offsets: offsetof(vm_area_struct, vm_flags) = %zu\n",
            offsetof(struct vm_area_struct, vm_flags));

    pr_info("offsets: offsetof(vm_struct, addr)  = %zu\n",
            offsetof(struct vm_struct, addr));
    pr_info("offsets: offsetof(vm_struct, phys_addr) = %zu\n",
            offsetof(struct vm_struct, phys_addr));

    pr_info("offsets: PAGE_SHIFT    = %d\n", PAGE_SHIFT);
    pr_info("offsets: PAGE_SIZE     = %lu (0x%lx)\n", (unsigned long)PAGE_SIZE, (unsigned long)PAGE_SIZE);
    pr_info("offsets: PAGE_MASK     = 0x%lx\n", (unsigned long)PAGE_MASK);
    pr_info("offsets: PAGE_OFFSET   = 0x%lx\n", (unsigned long)PAGE_OFFSET);
    pr_info("offsets: PHYS_MASK     = 0x%llx\n", (unsigned long long)PHYS_MASK);

    /* struct file -> f_path */
    pr_info("offsets: offsetof(file, f_path) = %zu\n",
            offsetof(struct file, f_path));

    /* struct path -> dentry (path.dentry) */
    pr_info("offsets: offsetof(path, dentry) = %zu\n",
            offsetof(struct path, dentry));

    /* struct dentry -> d_name (qstr) */
    pr_info("offsets: offsetof(dentry, d_name) = %zu\n",
            offsetof(struct dentry, d_name));

    /* struct qstr -> name (char *) */
    /* d_name is struct qstr with fields .name (const unsigned char *), .len, .hash */
    pr_info("offsets: offsetof(qstr, name) = %zu\n",
            offsetof(struct qstr, name));

    pr_info("offsets: offsetof(task_struct, comm) = %zu\n",
            offsetof(struct task_struct, comm));

    pr_info("offsets: offsetof(task_struct, pid) = %zu\n",
            offsetof(struct task_struct, pid));

    pr_info("offsets: offsetof(task_struct, tasks) = %zu\n",
        offsetof(struct task_struct, tasks));

    // new

    pr_info("offsets: offsetof(input_dev, name) = %zu\n",
            offsetof(struct input_dev, name));

    pr_info("offsets: offsetof(input_dev, mt) = %zu\n",
            offsetof(struct input_dev, mt));

    pr_info("offsets: offsetof(input_dev, event_lock) = %zu\n",
            offsetof(struct input_dev, event_lock));

    pr_info("offsets: offsetof(input_dev, mutex) = %zu\n",
        offsetof(struct input_dev, mutex));

    pr_info("offsets: offsetof(input_dev, node) = %zu\n",
        offsetof(struct input_dev, node));

    //pr_info("offsets: offsetof(task_struct, next) = %zu\n",
        //offsetof(struct task_struct, next));
    
    pr_info("offsets: DONE\n");
    return 0;
}

static void __exit offsets_exit(void)
{
    pr_info("offsets: exit\n");
}

module_init(offsets_init);
module_exit(offsets_exit);
