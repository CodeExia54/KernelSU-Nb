//
// server.h - Single-header kernel server module for proto family socket interface
// Created by assistant based on user's code on 2025-09-09
//

#ifndef SERVER_H
#define SERVER_H

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <net/busy_poll.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/input/mt.h>
#include <linux/input-event-codes.h>

// Include your local headers or forward declarations of missing
// functions like get_module_base(), access_process_vm_by_pid(),
// read/write_process_memory_ioremap(), system_supports_mte(), remap_process_memory(), etc.
// For this example, they are assumed available externally.

#define MAX_CACHE_KERNEL_ADDRESS_COUNT 16

#define REQ_GET_PROCESS_PID                  0
#define REQ_IS_PROCESS_PID_ALIVE             1
#define REQ_ATTACH_PROCESS                   2
#define REQ_GET_PROCESS_MODULE_BASE          3
#define REQ_READ_PROCESS_MEMORY_IOREMAP      4
#define REQ_WRITE_PROCESS_MEMORY_IOREMAP     5
#define REQ_ACCESS_PROCESS_VM                6
#define REQ_READ_PROCESS_MEMORY              7
#define REQ_WRITE_PROCESS_MEMORY             8
#define REMAP_MEMORY                        9

//#define CMD_TOUCH_CLICK_DOWN                1000
//#define CMD_TOUCH_CLICK_UP                  1001
//#define CMD_TOUCH_MOVE                     1006
// #define CMD_COPY_PROCESS                  1007   // COMMENTED - extra function
#define CMD_PROCESS_MALLOC                 1008
#define CMD_HIDE_VMA                      1009

struct req_access_process_vm {
    pid_t from;
    void __user* from_addr;
    pid_t to;
    void __user* to_addr;
    size_t size;
};

struct touch_event_base {
    int slot;
    int x;
    int y;
    int pressure;
};

/*
struct copy_process_args {
    void* fn;
    void* arg;
};
*/

struct hide_vma_args {
    unsigned long ptr;
    enum hide_mode: int {
        HIDE_X = 0,
        HIDE_NAME = 1, // TODO
        HIDE_ADDR = 2, // TODO
    } mode;
};

// pvm_sock struct for socket private data
struct pvm_sock {
    pid_t pid;
    atomic_t remap_in_progress;
    unsigned long pfn;

    unsigned long cached_kernel_pages[MAX_CACHE_KERNEL_ADDRESS_COUNT];
    size_t cached_count;
};

// --- Forward declarations ---
// These function prototypes should be visible to your module code
static int init_server(void);
static void exit_server(void);

// --- Implementation ---

// Release function: free cached pages and release socket references
static int pvm_release(struct socket *sock) {
    struct sock *sk = sock->sk;
    if (!sk) {
        return 0;
    }

    struct pvm_sock *os = (struct pvm_sock*)((char *)sk + sizeof(struct sock));
    int i;
    for (i = 0; i < os->cached_count; i++) {
        if (os->cached_kernel_pages[i]) {
            free_page(os->cached_kernel_pages[i]);
        }
    }

    sock_orphan(sk);
    sock_put(sk);

    // pr_info("[pvm] PVM socket released!\n");
    return 0;
}

// Poll stub (no events)
static __poll_t pvm_poll(struct file *file, struct socket *sock,
                         struct poll_table_struct *wait) {
    return 0;
}

// Setsockopt stub, returns protocol not supported for all options
static int pvm_setsockopt(struct socket *sock, int level, int optname,
                          sockptr_t optval, unsigned int optlen) {
    (void)sock; (void)level; (void)optname; (void)optval; (void)optlen;
    return -ENOPROTOOPT;
}

// Inline stub for getting process PID (commented out, returns 0)
static __always_inline int pvm_get_process_pid(int len, char __user *process_name_user) {
    /*
    int err;
    pid_t pid;
    char* process_name;

    process_name = kmalloc(len, GFP_KERNEL);
    if (!process_name) {
        return -ENOMEM;
    }

    if (copy_from_user(process_name, process_name_user, len)) {
        err = -EFAULT;
        goto out_proc_name;
    }

    pid = find_process_by_name(process_name);
    if (pid < 0) {
        err = -ESRCH;
        goto out_proc_name;
    }

    err = put_user((int) pid, (pid_t*) process_name_user);
    if (err)
        goto out_proc_name;

out_proc_name:
    kfree(process_name);

    return err;
    */
    return 0;
}

// Get process module base address using user-provided module name
// Commented because it depends on external function get_module_base()
/*
static __always_inline int pvm_get_process_module_base(int len, pid_t pid,
                                                       char __user *module_name_user, int flag) {
    int err;
    char* module_name;

    module_name = kmalloc(len, GFP_KERNEL);
    if (!module_name) {
        return -ENOMEM;
    }

    if (copy_from_user(module_name, module_name_user, len)) {
        err = -EFAULT;
        goto out_module_name;
    }

    uintptr_t base = get_module_base(pid, module_name, flag);
    if (base == 0) {
        err = -ENAVAIL;
        goto out_module_name;
    }

    err = put_user((uintptr_t) base, (uintptr_t*)module_name_user);
    if (err)
        goto out_module_name;

out_module_name:
    kfree(module_name);
    return err;
}
*/

// Getsockopt handler with interaction commands partially commented
static int pvm_getsockopt(struct socket *sock, int level, int optname,
                          char __user *optval, int __user *optlen) {
    struct sock* sk;
    struct pvm_sock* os;
    int len, alive, ret;
    //unsigned long pfn;

    sk = sock->sk;
    if (!sk)
        return -EINVAL;
    os = ((struct pvm_sock*)((char *) sock->sk + sizeof(struct sock)));

    pr_debug("[pvm] getsockopt: %d\n", optname);
    switch (optname) {
        case REQ_GET_PROCESS_PID: {
            ret = pvm_get_process_pid(level, optval);
            if (ret) {
                pr_err("[pvm] pvm_get_process_pid failed: %d\n", ret);
            }
            break;
        }
        case REQ_IS_PROCESS_PID_ALIVE: {
            alive = is_pid_alive(level);
            if (put_user(alive, optlen)) {
                return -EAGAIN;
            }
            ret = 0;
            break;
        }
        case REQ_ATTACH_PROCESS: {
            if (is_pid_alive(level) == 0) {
                return -ESRCH;
            }
            os->pid = level;
            pr_info("[pvm] attached process: %d\n", level);
            ret = 0;
            break;
        }
        case REQ_ACCESS_PROCESS_VM: {
            if (get_user(len, optlen))
                return -EFAULT;

            if (len < (int)sizeof(struct req_access_process_vm))
                return -EINVAL;

            struct req_access_process_vm req;
            if (copy_from_user(&req, optval, sizeof(struct req_access_process_vm)))
                return -EFAULT;

            // Commented out because depends on external function access_process_vm_by_pid()
            /*
            ret = access_process_vm_by_pid(req.from, req.from_addr,
                                          req.to, req.to_addr, req.size);
            */
            ret = -ENOSYS;
            break;
        }
        default:
            ret = 114514;
            break;
    }

    if (ret <= 0) {
        // Return special code for zero or pass negative errors directly
        if (ret == 0) {
            return -2033;
        } else {
            return ret;
        }
    }

    // Verify attached process valid and alive
    if (os->pid <= 0 || is_pid_alive(os->pid) == 0) {
        return -ESRCH;
    }

    switch (optname) {
        case REQ_GET_PROCESS_MODULE_BASE: {
            if (get_user(len, optlen))
                return -EFAULT;
            if (len < 0)
                return -EINVAL;

            // Commented out because depends on pvm_get_process_module_base()
            /*
            ret = pvm_get_process_module_base(len, os->pid, optval, level);
            */
            ret = -ENOSYS;
            break;
        }
        case REQ_READ_PROCESS_MEMORY_IOREMAP: {
            // Commented out because depends on read_process_memory_ioremap()
            /*
            if ((ret = read_process_memory_ioremap(os->pid, (void *)optval, (void *)optlen, level))) {
                pr_debug("[pvm] read_process_memory_ioremap failed: %d\n", ret);
            }
            */
            ret = -ENOSYS;
            break;
        }
        case REQ_WRITE_PROCESS_MEMORY_IOREMAP: {
            // Commented out because depends on write_process_memory_ioremap()
            /*
            ret = write_process_memory_ioremap(os->pid, (void *)optval, (void *)optlen, level);
            */
            ret = -ENOSYS;
            break;
        }
        case REQ_READ_PROCESS_MEMORY: {
            // Commented out because depends on read_process_memory()
            /*
            ret = read_process_memory(os->pid, (void *)optval, (void *)optlen, level);
            */
            ret = -ENOSYS;
            break;
        }
        case REQ_WRITE_PROCESS_MEMORY: {
            // Commented out because depends on write_process_memory()
            /*
            ret = write_process_memory(os->pid, (void *)optval, (void *)optlen, level);
            */
            ret = -ENOSYS;
            break;
        }
        case REMAP_MEMORY: {
            if (atomic_cmpxchg(&os->remap_in_progress, 0, 1) != 0)
                return -EBUSY;

            // Commented out because depends on process_vaddr_to_pfn()
            /*
            ret = process_vaddr_to_pfn(os->pid, optval, &pfn, level);
            if (!ret) {
                os->pfn = pfn;
            } else {
                atomic_set(&os->remap_in_progress, 0);
                os->pfn = 0;
            }
            */
            atomic_set(&os->remap_in_progress, 0);
            os->pfn = 0;
            ret = -ENOSYS;
            break;
        }
        default:
            ret = 114514;
            break;
    }

    if (ret <= 0) {
        if (ret == 0)
            return -2033;
        else
            return ret;
    }

    return -EOPNOTSUPP;
}

// mmap handler to remap process memory into user area
static int pvm_mmap(struct file *file, struct socket *sock,
                    struct vm_area_struct *vma) {
    int ret;
    struct pvm_sock *os;

    if (!sock->sk) {
        return -EINVAL;
    }
    os = (struct pvm_sock*)((char *) sock->sk + sizeof(struct sock));

    atomic_set(&os->remap_in_progress, 0);

    if (os->pid <= 0 || is_pid_alive(os->pid) == 0) {
        return -ESRCH;
    }

    if (!os->pfn) {
        return -EFAULT;
    }

    if (system_supports_mte()) {
        // vm_flags_set(vma, VM_MTE);
    }

    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
    // vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

    // Commented out because depends on remap_process_memory()
    /*
    ret = remap_process_memory(vma, os->pfn, vma->vm_end - vma->vm_start);
    if (!ret) {
        pr_err("[pvm] remap_process_memory failed: %d\n", ret);
    }
    */
    ret = -ENOSYS;
    return ret;
}

// ioctl handler with touch commands and process memory allocation
static int pvm_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
    /*
    struct event_pool* pool;
    unsigned long flags;

    pool = get_event_pool();
    if (pool == NULL) {
        return -ECOMM;
    }

    struct touch_event_base __user* event_user = (struct touch_event_base __user*) arg;
    struct touch_event_base event;

    if (!event_user) {
        return -EBADR;
    }

    if (copy_from_user(&event, event_user, sizeof(struct touch_event_base))) {
        return -EACCES;
    }

    if (cmd == CMD_TOUCH_CLICK_DOWN) {
        spin_lock_irqsave(&pool->event_lock, flags);

        if (pool->size >= MAX_EVENTS) {
            pr_warn("[pvm] event pool is full!\n");
            pool->size = 0;
        }

        input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
        int id = input_mt_report_slot_state_with_id_cache(MT_TOOL_FINGER, 1, event.slot, 0);
        input_event_cache(EV_ABS, ABS_MT_POSITION_X, event.x, 0);
        input_event_cache(EV_ABS, ABS_MT_POSITION_Y, event.y, 0);
        input_event_cache(EV_ABS, ABS_MT_PRESSURE, event.pressure, 0);
        input_event_cache(EV_ABS, ABS_MT_TOUCH_MAJOR, event.pressure, 0);
        input_event_cache(EV_ABS, ABS_MT_TOUCH_MINOR, event.pressure, 0);

        event.pressure = id;
        if (copy_to_user(event_user, &event, sizeof(struct touch_event_base))) {
            pr_err("[pvm] copy_to_user failed: %s\n", __func__);
            spin_unlock_irqrestore(&pool->event_lock, flags);
            return -EACCES;
        }

        spin_unlock_irqrestore(&pool->event_lock, flags);
        return -2033;
    }
    if (cmd == CMD_TOUCH_CLICK_UP) {
        spin_lock_irqsave(&pool->event_lock, flags);

        if (pool->size >= MAX_EVENTS) {
            pr_warn("[pvm] event pool is full!\n");
            pool->size = 0;
        }

        input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
        input_mt_report_slot_state_cache(MT_TOOL_FINGER, 0, 0);

        spin_unlock_irqrestore(&pool->event_lock, flags);
        return -2033;
    }
    if (cmd == CMD_TOUCH_MOVE) {
        spin_lock_irqsave(&pool->event_lock, flags);

        if (pool->size >= MAX_EVENTS) {
            pr_warn("[pvm] event pool is full!\n");
            pool->size = 0;
        }

        input_event_cache(EV_ABS, ABS_MT_SLOT, event.slot, 0);
        input_event_cache(EV_ABS, ABS_MT_POSITION_X, event.x, 0);
        input_event_cache(EV_ABS, ABS_MT_POSITION_Y, event.y, 0);
        input_event_cache(EV_SYN, SYN_MT_REPORT, 0, 0);

        spin_unlock_irqrestore(&pool->event_lock, flags);
        return -2033;
    }
    */

    /*
    // Commented out: extra function, not needed
    if (cmd == CMD_COPY_PROCESS) {
        // ...
    }
    */

    if (cmd == CMD_PROCESS_MALLOC) {
        if (!sock->sk) {
            return -EINVAL;
        }

        struct pvm_sock *os = (struct pvm_sock *)((char *) sock->sk + sizeof(struct sock));
        if (os->pid == 0) {
            return -ESRCH;
        }

        int writable = 0;
        if (get_user(writable, (int*) arg)) {
            return -EACCES;
        }

        if (os->cached_count >= MAX_CACHE_KERNEL_ADDRESS_COUNT) {
            pr_err("[pvm] cached_addr_array is full!\n");
            return -ENOMEM;
        }

        if (atomic_cmpxchg(&os->remap_in_progress, 0, 1) != 0)
            return -EBUSY;

        struct pid *pid_struct = find_get_pid(os->pid);
        if (!pid_struct) {
            pr_err("[pvm] failed to find pid_struct: %s\n", __func__);
            return -ESRCH;
        }

        struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
        put_pid(pid_struct);
        if (!task) {
            pr_err("[pvm] failed to get task from pid_struct: %s\n", __func__);
            return -ESRCH;
        }

        struct mm_struct *mm = get_task_mm(task);
        put_task_struct(task);
        if (!mm) {
            pr_err("[pvm] failed to get mm from task: %s\n", __func__);
            return -ESRCH;
        }

        MM_READ_LOCK(mm);
        unsigned long addr = 0;
        get_unmapped_area_mm(mm, &addr, PAGE_SIZE);

        if (addr == 0) {
            MM_READ_UNLOCK(mm);
            mmput(mm);
            atomic_set(&os->remap_in_progress, 0);
            pr_err("[pvm] get_unmapped_area_mm failed: %s\n", __func__);
            return -ENOMEM;
        }

        // Commented out because alloc_process_special_memory_mm() not defined
        /*
        if (alloc_process_special_memory_mm(mm, addr, PAGE_SIZE, writable)) {
            MM_READ_UNLOCK(mm);
            mmput(mm);
            atomic_set(&os->remap_in_progress, 0);
            pr_err("[pvm] alloc_process_special_memory_mm failed: %s\n", __func__);
            return -ENOMEM;
        }
        */

        MM_READ_UNLOCK(mm);
        mmput(mm);

        unsigned long kaddr = get_zeroed_page(GFP_KERNEL);
        if (!kaddr) {
            pr_err("[pvm] kmalloc failed!: %s\n", __func__);
            atomic_set(&os->remap_in_progress, 0);
            return -ENOMEM;
        }

        if (put_user(addr, (unsigned long __user*) arg) ||
            put_user((unsigned long) PAGE_SIZE, (unsigned long __user*) (arg + sizeof(unsigned long)))) {
            free_page(kaddr);
            atomic_set(&os->remap_in_progress, 0);
            return -EACCES;
        }

        unsigned long pfn = __phys_to_pfn(__virt_to_phys(kaddr));
        if (insert_addr_pfn(addr, pfn) < 0) {
            free_page(kaddr);
            atomic_set(&os->remap_in_progress, 0);
            return -EEXIST;
        }

        os->cached_kernel_pages[os->cached_count++] = kaddr;
        os->pfn = pfn;

        pr_info("[pvm] malloced kernel address: 0x%lx, pfn: 0x%lx, magic: 0x%lx\n",
                kaddr, pfn, *(unsigned long*)kaddr);
        return -2033;
    }

    if (cmd == CMD_HIDE_VMA) {
        if (!sock->sk) {
            return -EINVAL;
        }

        struct pvm_sock *os = (struct pvm_sock *) ((char *)sock->sk + sizeof(struct sock));
        if (os->pid == 0) {
            return -ESRCH;
        }

        struct hide_vma_args args;
        if (copy_from_user(&args, (struct hide_vma_args __user*) arg, sizeof(struct hide_vma_args))) {
            pr_err("[pvm] copy_from_user failed: %s\n", __func__);
            return -EACCES;
        }

        // Commented out because find_vma_pid() is undefined here
        /*
        struct vm_area_struct *vma = find_vma_pid(os->pid, args.ptr);
        if (!vma) {
            return -ESRCH;
        }

        if (args.mode == HIDE_X) {
            // vm_flags_clear(vma, VM_EXEC);
        } else {
            pr_warn("[pvm] hide mode not supported!\n");
            return -ENOSYS;
        }
        */

        return -ENOSYS;
    }

    return -ENOTTY;
}

// sendmsg stub - no implementation
static int pvm_sendmsg(struct socket *sock, struct msghdr *m,
                       size_t total_len) {
    (void)sock; (void)m; (void)total_len;
    return 0;
}

// Proto and proto_ops struct definitions
static struct proto pvm_proto = {
    .name = "PVM_LLCP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct sock) + sizeof(struct pvm_sock),
};

static struct proto_ops pvm_proto_ops = {
    .family = PF_DECnet,
    .owner = THIS_MODULE,
    .release = pvm_release,
    .bind = sock_no_bind,
    .connect = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = sock_no_getname,
    .poll = pvm_poll,
    .ioctl = pvm_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = pvm_setsockopt,
    .getsockopt = pvm_getsockopt,
    .sendmsg = pvm_sendmsg,
    .recvmsg = sock_no_recvmsg,
    .mmap = pvm_mmap,
};

static int free_family = AF_DECnet;

static int pvm_create(struct net *net, struct socket *sock, int protocol,
                        int kern) {
    uid_t caller_uid;
    struct sock *sk;
    struct pvm_sock *os;

    caller_uid = *((uid_t*) &current_cred()->uid);
    if (caller_uid != 0) {
        pr_warn("[pvm] Only root can create PVM socket!\n");
        return -EAFNOSUPPORT;
    }

    if (sock->type != SOCK_RAW) {
        // pr_warn("[pvm] a PVM socket must be SOCK_RAW!\n");
        return -ENOKEY;
    }

    sock->state = SS_UNCONNECTED;

    sk = sk_alloc(net, PF_INET, GFP_KERNEL, &pvm_proto, kern);
    if (!sk) {
        pr_warn("[pvm] sk_alloc failed!\n");
        return -ENOBUFS;
    }

    os = (struct pvm_sock*)((char *) sk + sizeof(struct sock));

    pvm_proto_ops.family = free_family;
    sock->ops = &pvm_proto_ops;
    sock_init_data(sock, sk);

    // Initialize pvm_sock
    os->pid = 0;
    os->pfn = 0;
    atomic_set(&os->remap_in_progress, 0);
    os->cached_count = 0;

    return 0;
}

static struct net_proto_family pvm_family_ops = {
    .family = PF_DECnet,
    .create = pvm_create,
    .owner = THIS_MODULE,
};

static int register_free_family(void) {
    int family;
    int err;
    for (family = free_family; family < NPROTO; family++) {
        pvm_family_ops.family = family;
        err = sock_register(&pvm_family_ops);
        if (err)
            continue;
        else {
            free_family = family;
            pr_info("[pvm] Find free proto_family: %d\n", free_family);
            return 0;
        }
    }

    pr_err("[pvm] Can't find any free proto_family!\n");
    return err;
}

// Init server: register protocol and socket family
static int init_server(void) {
    int err;

    err = proto_register(&pvm_proto, 1);
    if (err)
        goto out;

    err = register_free_family();
    if (err)
        goto out_proto;

    return 0;

out_proto:
    proto_unregister(&pvm_proto);
out:
    return err;
}

// Exit server: unregister proto and socket family
static void exit_server(void) {
    sock_unregister(free_family);
    proto_unregister(&pvm_proto);
}

#endif // SERVER_H
