# Rootkit 故障排除指南

本文档提供了在编译和使用rootkit过程中可能遇到的常见问题及其解决方案。

## 🚨 编译错误

### 1. 结构体重复定义错误

**错误信息**:
```
error: redefinition of 'struct linux_dirent64'
```

**原因**: 在Linux内核5.6+版本中，`linux_dirent64`结构体已在内核头文件中定义。

**解决方案**:
```bash
# 运行自动修复脚本
./apply_kernel_fix.sh
```

或手动修复：
1. 在`rootkit.h`中为`linux_dirent64`结构体添加条件编译：
```c
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct linux_dirent64 {
    // 结构体定义
};
#endif
```

### 2. proc_find_entry函数未定义

**错误信息**:
```
error: implicit declaration of function 'proc_find_entry'
```

**原因**: 在较新的内核版本中，`proc_find_entry`函数不再导出给模块使用。

**解决方案**:
```bash
# 运行自动修复脚本
./apply_kernel_fix.sh
```

或手动修复：
1. 在`module_hiding.c`中添加版本检查：
```c
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
    // 使用proc_find_entry的代码
#else
    // 跳过或使用替代方法
#endif
```

### 3. THIS_MODULE重复声明

**错误信息**:
```
error: expected identifier or '(' before '&' token
```

**原因**: `THIS_MODULE`已在内核头文件中定义为宏。

**解决方案**:
移除`extern struct module *THIS_MODULE;`声明。

### 4. original_proc_modules_fops未声明

**错误信息**:
```
error: 'original_proc_modules_fops' undeclared (first use in this function)
```

**解决方案**:
该变量被条件编译保护，但使用它的函数没有相应保护。在使用该变量的地方添加条件编译:
```c
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
    original_proc_modules_fops ? "Yes" : "No"
#else
    "Not Supported"
#endif
```

### 5. __NR_newfstat系统调用号未定义

**错误信息**:
```
error: '__NR_newfstat' undeclared (first use in this function)
```

**解决方案**:
在Linux内核5.15及更高版本中，`__NR_newfstat` 被替换为 `__NR_fstat`。需要添加条件编译:
```c
#ifdef __NR_newfstat
    original_stat = (void *)sys_call_table[__NR_newfstat];
#elif defined(__NR_fstat)
    original_stat = (void *)sys_call_table[__NR_fstat];
#else
    original_stat = NULL;
    printk(KERN_WARNING "[rootkit] stat syscall not available\n");
#endif
```

## 7. port_hiding.c函数重定义和宏未定义错误

**错误信息**:
```
port_hiding.c:82:12: error: redefinition of 'is_magic_port'
port_hiding.c:84:26: error: 'MAGIC_PORT_RANGE_START' undeclared
port_hiding.c:89:50: error: 'ROOTKIT_PORT' undeclared
```

**原因**: 
1. `is_magic_port` 函数在 `rootkit.h` 中已定义，在 `port_hiding.c` 中重复定义
2. 使用了未在 `rootkit.h` 中定义的宏 `MAGIC_PORT_RANGE_START`、`MAGIC_PORT_RANGE_END`、`ROOTKIT_PORT`

**解决方案**:
1. 删除 `port_hiding.c` 中重复的 `is_magic_port` 函数定义
2. 将未定义的宏替换为已定义的宏：
   - `MAGIC_PORT_RANGE_START` → `MAGIC_PORT_START`
   - `MAGIC_PORT_RANGE_END` → `MAGIC_PORT_END`
   - `ROOTKIT_PORT` → `CONTROL_PORT`
3. 修正函数调用参数类型：`is_magic_port(ntohs(port))`

## 8. 模块链接错误 - 符号未定义

**错误信息**:
```
ERROR: modpost: missing MODULE_LICENSE() in /root/rootkit/rootkit.o
ERROR: modpost: "module_previous" [/root/rootkit/rootkit.ko] undefined!
ERROR: modpost: "sys_call_table" [/root/rootkit/rootkit.ko] undefined!
ERROR: modpost: "enable_write_protection" [/root/rootkit/rootkit.ko] undefined!
ERROR: modpost: "disable_write_protection" [/root/rootkit/rootkit.ko] undefined!
ERROR: modpost: "module_hidden" [/root/rootkit/rootkit.ko] undefined!
```

**原因**:
- `module_previous`和`module_hidden`变量被声明为`static`，无法被其他模块访问
- 缺少必要的`EXPORT_SYMBOL`声明
- 模块许可证信息可能位置不正确

**解决方案**:
1. 将`static`变量改为全局变量
2. 添加`EXPORT_SYMBOL`导出符号
3. 确保`MODULE_LICENSE`等宏定义正确

**修复命令**:
```bash
# 修改变量声明
sed -i 's/static struct list_head \*module_previous;/struct list_head *module_previous;/' main.c
sed -i 's/static short module_hidden = 0;/short module_hidden = 0;/' main.c

# 添加符号导出
sed -i '/EXPORT_SYMBOL(enable_write_protection);/a\
EXPORT_SYMBOL(module_previous);\
EXPORT_SYMBOL(module_hidden);' main.c
```

## 9. 内核头文件未找到

**错误信息**:
```
fatal error: linux/module.h: No such file or directory
```

**解决方案**:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install kernel-devel kernel-headers

# Fedora
sudo dnf install kernel-devel kernel-headers

# Arch Linux
sudo pacman -S linux-headers
```

## 10. 编译器版本不匹配警告

**警告信息**:
```
warning: the compiler differs from the one used to build the kernel
```

**原因**: 编译模块的GCC版本与编译内核的GCC版本不同。

**解决方案**:
这通常只是警告，不会影响功能。如果需要解决：
```bash
# 安装与内核匹配的GCC版本
sudo apt install gcc-11  # 根据内核编译版本调整

# 或者忽略此警告继续编译
make EXTRA_CFLAGS="-w"
```

## 11. 循环依赖警告

**警告信息**:
```
Circular /path/to/rootkit.o <- /path/to/rootkit.o dependency dropped
```

**原因**: Makefile中的依赖关系配置问题。

**解决方案**:
这通常不影响编译，可以忽略。如果需要修复，检查Makefile中的目标依赖关系。

## 🔧 运行时错误

### 1. 模块加载失败

**错误信息**:
```
insmod: ERROR: could not insert module rootkit.ko: Operation not permitted
```

**可能原因和解决方案**:

1. **权限不足**:
```bash
sudo insmod rootkit.ko
```

2. **Secure Boot启用**:
```bash
# 检查Secure Boot状态
mokutil --sb-state

# 如果启用，需要签名模块或禁用Secure Boot
```

3. **内核模块签名验证**:
```bash
# 临时禁用模块签名验证（不推荐用于生产环境）
echo 0 | sudo tee /proc/sys/kernel/modules_disabled
```

### 2. 版本魔数不匹配

**错误信息**:
```
insmod: ERROR: could not insert module rootkit.ko: Invalid module format
dmesg: disagrees about version of symbol module_layout
```

**解决方案**:
```bash
# 重新编译模块
make clean && make

# 确保使用正确的内核头文件
ls /lib/modules/$(uname -r)/build
```

### 3. 符号未找到

**错误信息**:
```
insmod: ERROR: could not insert module rootkit.ko: Unknown symbol in module
```

**解决方案**:
```bash
# 检查缺失的符号
dmesg | tail

# 确保所有依赖的内核符号都可用
grep -r "symbol_name" /proc/kallsyms
```

## 🖥️ 环境问题

### 1. 在macOS上编译

**错误信息**:
```
This rootkit can only be compiled on Linux systems
```

**解决方案**:
此rootkit只能在Linux系统上编译和运行。请使用：
- Linux虚拟机（VMware、VirtualBox）
- Linux服务器
- WSL2（Windows Subsystem for Linux）

### 2. Docker容器中编译

**问题**: Docker容器通常不支持加载内核模块。

**解决方案**:
```bash
# 使用特权容器（仅用于编译测试）
docker run --privileged -v /lib/modules:/lib/modules:ro ubuntu:22.04

# 或者在宿主机上编译，容器中开发
```

### 3. 虚拟机中的问题

**常见问题**:
- 虚拟化功能未启用
- 内存不足
- 内核头文件缺失

**解决方案**:
```bash
# 确保虚拟机配置
# - 至少2GB内存
# - 启用虚拟化功能
# - 安装完整的开发工具

sudo apt install build-essential linux-headers-$(uname -r)
```

## 🔍 调试技巧

### 1. 查看内核日志

```bash
# 实时查看内核消息
sudo dmesg -w

# 查看最近的内核消息
dmesg | tail -20

# 过滤rootkit相关消息
dmesg | grep -i rootkit
```

### 2. 检查模块状态

```bash
# 列出已加载的模块
lsmod | grep rootkit

# 查看模块详细信息
modinfo rootkit.ko

# 查看模块依赖
modprobe --show-depends rootkit
```

### 3. 编译调试版本

```bash
# 启用调试信息
make EXTRA_CFLAGS="-DDEBUG -g"

# 或者修改Makefile添加调试标志
echo "EXTRA_CFLAGS += -DDEBUG" >> Makefile
```

## 📋 检查清单

在报告问题之前，请确认以下项目：

- [ ] 运行在Linux系统上（不是macOS或Windows）
- [ ] 已安装内核头文件：`ls /lib/modules/$(uname -r)/build`
- [ ] 已安装编译工具：`gcc --version && make --version`
- [ ] 内核版本兼容：`uname -r`（推荐5.15.x）
- [ ] 有root权限：`sudo -v`
- [ ] 已尝试运行修复脚本：`./apply_kernel_fix.sh`
- [ ] 已查看内核日志：`dmesg | tail`

## 🆘 获取帮助

如果以上解决方案都无法解决问题，请提供以下信息：

1. **系统信息**:
```bash
uname -a
cat /etc/os-release
```

2. **编译环境**:
```bash
gcc --version
make --version
ls -la /lib/modules/$(uname -r)/build
```

3. **完整的错误信息**:
```bash
make clean && make 2>&1 | tee compile.log
```

4. **内核日志**:
```bash
dmesg | tail -50
```

## ⚠️ 安全提醒

- 仅在测试环境中使用此rootkit
- 不要在生产系统上安装
- 遵守当地法律法规
- 使用完毕后及时卸载：`sudo rmmod rootkit`

---

**注意**: 此故障排除指南会根据用户反馈持续更新。如果遇到新的问题，请及时反馈。