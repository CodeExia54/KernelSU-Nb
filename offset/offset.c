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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("offset-printer");
MODULE_DESCRIPTION("Print offsets for mm/vma/file/dentry fields");

static int __init offsets_init(void)
{
    pr_info("offsets: sizeof(void*)=%zu, sizeof(unsigned long)=%zu\n",
            sizeof(void *), sizeof(unsigned long));

    /* mm_struct -> mmap */
    pr_info("offsets: offsetof(mm_struct, mmap) = %zu\n",
            offsetof(struct mm_struct, mmap));

    /* vm_area_struct fields */
    pr_info("offsets: offsetof(vm_area_struct, vm_next) = %zu\n",
            offsetof(struct vm_area_struct, vm_next));
    pr_info("offsets: offsetof(vm_area_struct, vm_start) = %zu\n",
            offsetof(struct vm_area_struct, vm_start));
    pr_info("offsets: offsetof(vm_area_struct, vm_file)  = %zu\n",
            offsetof(struct vm_area_struct, vm_file));
    pr_info("offsets: offsetof(vm_area_struct, vm_flags) = %zu\n",
            offsetof(struct vm_area_struct, vm_flags));

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

    pr_info("offsets: DONE\n");
    return 0;
}

static void __exit offsets_exit(void)
{
    pr_info("offsets: exit\n");
}

module_init(offsets_init);
module_exit(offsets_exit);
