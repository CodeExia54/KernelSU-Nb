#ifndef SERVER_H
#define SERVER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/pid.h>

#define MAX_CACHE_KERNEL_ADDRESS_COUNT 16

struct pvm_sock {
    pid_t pid;
    atomic_t remap_in_progress;
    unsigned long pfn;
    unsigned long cached_kernel_pages[MAX_CACHE_KERNEL_ADDRESS_COUNT];
    size_t cached_count;
};

static int pvm_release(struct socket *sock) {
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;

    struct pvm_sock *os = (struct pvm_sock *)((char *)sk + sizeof(struct sock));
    for (size_t i = 0; i < os->cached_count; i++) {
        if (os->cached_kernel_pages[i]) {
            free_page(os->cached_kernel_pages[i]);
        }
    }

    sock_orphan(sk);
    sock_put(sk);
    return 0;
}

static __poll_t pvm_poll(struct file *file, struct socket *sock,
                         struct poll_table_struct *wait) {
    return 0;
}

static int pvm_setsockopt(struct socket *sock, int level, int optname,
                          sockptr_t optval, unsigned int optlen) {
    return -ENOPROTOOPT;
}

static int pvm_getsockopt(struct socket *sock, int level, int optname,
                          char __user *optval, int __user *optlen) {
    return -ENOSYS;
}

static int pvm_sendmsg(struct socket *sock, struct msghdr *m,
                       size_t total_len) {
    return 0;
}

static int pvm_mmap(struct file *file, struct socket *sock,
                    struct vm_area_struct *vma) {
    return -ENOSYS;
}

static int pvm_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
    return -ENOTTY;
}

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

static int pvm_create(struct net *net, struct socket *sock, int protocol, int kern) {
    uid_t caller_uid = *((uid_t*)&current_cred()->uid);
    if (caller_uid != 0) {
        pr_warn("[pvm] Only root can create PVM socket!\n");
        return -EAFNOSUPPORT;
    }

    if (sock->type != SOCK_RAW) {
        return -ENOKEY;
    }

    sock->state = SS_UNCONNECTED;

    struct sock *sk = sk_alloc(net, PF_INET, GFP_KERNEL, &pvm_proto, kern);
    if (!sk) {
        pr_warn("[pvm] sk_alloc failed!\n");
        return -ENOBUFS;
    }

    struct pvm_sock *os = (struct pvm_sock *)((char *)sk + sizeof(struct sock));

    pvm_proto_ops.family = free_family;
    sock->ops = &pvm_proto_ops;
    sock_init_data(sock, sk);

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
    int err = 0;
    for (int family = free_family; family < NPROTO; family++) {
        pvm_family_ops.family = family;
        err = sock_register(&pvm_family_ops);
        if (!err) {
            free_family = family;
            pr_info("[pvm] Found free proto_family: %d\n", free_family);
            return 0;
        }
    }
    pr_err("[pvm] Unable to find any free proto_family! err=%d\n", err);
    return err;
}

static int init_server(void) {
    int err = proto_register(&pvm_proto, 1);
    if (err)
        return err;
    err = register_free_family();
    if (err)
        proto_unregister(&pvm_proto);
    return err;
}

static void exit_server(void) {
    sock_unregister(free_family);
    proto_unregister(&pvm_proto);
}

#endif // SERVER_H
