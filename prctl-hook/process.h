#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/rcupdate.h>

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#include <linux/dcache.h>
#include <linux/maple_tree.h>

// #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);

extern char *d_path(const struct path *, char *, int);
#endif

#define ARC_PATH_MAX 256

extern struct mm_struct *get_task_mm(struct task_struct *task);
extern void mmput(struct mm_struct *);

// Ref: https://elixir.bootlin.com/linux/v6.1.57/source/mm/mmap.c#L325
//      https://elixir.bootlin.com/linux/v6.1.57/source/fs/open.c#L998
uintptr_t traverse_vma(struct mm_struct* mm, char* name) {
    struct vm_area_struct *vma;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct ma_state mas = {
		.tree = &mm->mm_mt,
		.index = 0,
		.last = 0,
		.node = MAS_START,
		.min = 0,
		.max = ULONG_MAX,
		.alloc = NULL,
	};

    while ((vma = mas_find(&mas, ULONG_MAX)) != NULL)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
            path_nm = d_path(&(vma->vm_file)->f_path, buf, ARC_PATH_MAX-1);
#else
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
#endif
            pr_info("traverse_vma - path_nm: %s\n", path_nm);
            if (!strcmp(kbasename(path_nm), name)) {
                pr_info("traverse_vma - found: %lx\n", vma->vm_start);
                return vma->vm_start;
            }
        }
    }
    return 0;
}

int is_pid_alive(pid_t pid) {
    struct pid * pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

uintptr_t get_module_base(pid_t pid, char* name) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;

	// new
	struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    uintptr_t result;
	struct dentry *dentry;
	size_t name_len, dname_len;
	int vm_flag = 0x00000004;
	result = 0;

	if(!is_pid_alive(pid))
		return 0;

	name_len = strlen(name);
	if (name_len == 0) {
		pr_err("[pvm] module name is empty\n");
		return 0;
	}
	
/*
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    rcu_read_lock();
    pid_struct = find_vpid(pid);
    if (!pid_struct) {
        return false;
    }
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        pr_err("get_module_base pid_task failed.\n");
        return false;
    }
    rcu_read_unlock();
#else
	*/
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("get_module_base find_get_pid failed.\n");
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        pr_err("get_module_base get_pid_task failed.\n");
        return false;
    }
// #endif

    mm = get_task_mm(task);
	put_task_struct(task); // new
    if (!mm) {
        pr_err("get_module_base get_task_mm failed.\n");
        return false;
    }

	mmap_read_lock(mm);

	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
        for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
			if (vm_flag && !(vma->vm_flags & vm_flag)) {
				continue;
			}
			dentry = vma->vm_file->f_path.dentry;
			dname_len = dentry->d_name.len;
			if (!memcmp(dentry->d_name.name, name, min(name_len, dname_len))) {
				result = vma->vm_start;
				goto ret;
			}
        }
    }

    ret:
    mmap_read_unlock(mm);

    mmput(mm);
    return result;
    // mmput(mm);
    // return traverse_vma(mm, name);
}
