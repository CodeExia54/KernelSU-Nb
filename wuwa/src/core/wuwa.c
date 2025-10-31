#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "wuwa_common.h"
#include "wuwa_kallsyms.h"
#include "wuwa_protocol.h"
#include "wuwa_safe_signal.h"
#include "wuwa_sock.h"
#include "wuwa_utils.h"
#include "hijack_arm64.h"
#include <linux/fdtable.h>      /* Open file table structure: files_struct structure */
#include <linux/proc_ns.h>	

bool isPHook = false;
int pid_hide = 0;
#define PF_INVISIBLE 0x10000000

#include <linux/dirent.h>	/* struct dirent refers to directory entry. */

struct linux_dirent {
        unsigned long   d_ino;		/* inode number */
        unsigned long   d_off;		/* offset to the next dirent */
        unsigned short  d_reclen;	/* length of this record */
        char            d_name[1];	/* filename */
};

struct my_kretprobe_data {
    int sys_ns;
    pid_t pid;
    int fd;
    struct linux_dirent *dirent;
};

struct prctl_cf {
    int pid;
    uintptr_t addr;
    void* buffer;
    int size;
};

static int handler_post(struct kretprobe_instance *ri, struct pt_regs *regs)
// struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    uint64_t v4;
    return 0;
}

static int handler_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
// struct kprobe *p, struct pt_regs *regs)
{
    uint64_t v4;
    return 1;
}

static struct kretprobe my_kretprobe = {
    .kp.symbol_name = "invoke_syscall", /* or use .kp.addr */
    .handler = handler_post,                 /* return handler */
    .entry_handler = handler_pre,         /* entry handler */
    .data_size = sizeof(struct my_kretprobe_data),
    .maxactive = 512,                           /* concurrency depth */
};

static int __init wuwa_init(void) {
    int ret;
    wuwa_info("helo!\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    ret = disable_kprobe_blacklist();
    if (ret) {
        wuwa_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }
#endif

    ret = init_arch();
    if (ret) {
        wuwa_err("init_arch failed: %d\n", ret);
        return ret;
    }

    ret = wuwa_proto_init();
    if (ret) {
        wuwa_err("wuwa_socket_init failed: %d\n", ret);
        goto out;
    }

    ret = register_kretprobe(&my_kretprobe);
	// if(ret < 0) {
	if(ret) {
		isPHook = false;
	    wuwa_err("wuwa: driverX: Failed to register kprobe: %d (%s)\n", ret, kpp.symbol_name);
	    return ret;
	 } else {
		isPHook = true;
        wuwa_info("p probe success");
    }

#if defined(BUILD_HIDE_SIGNAL)
    ret = wuwa_safe_signal_init();
    if (ret) {
        wuwa_err("wuwa_safe_signal_init failed: %d\n", ret);
        goto clean_sig;
    }
#endif


#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    wuwa_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    return 0;

#if defined(BUILD_HIDE_SIGNAL)
clean_d0:
    wuwa_safe_signal_cleanup();

clean_sig:
    wuwa_proto_cleanup();
#endif


out:
    return ret;
}

static void __exit wuwa_exit(void) {
    wuwa_info("bye!\n");
    wuwa_proto_cleanup();
    if(isPHook) 
		unregister_kretprobe(&my_kretprobe);
#if defined(BUILD_HIDE_SIGNAL)
    wuwa_safe_signal_cleanup();
#endif
}

module_init(wuwa_init);
module_exit(wuwa_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/android-wuwa");
MODULE_VERSION("1.0.5");

MODULE_IMPORT_NS(DMA_BUF);
