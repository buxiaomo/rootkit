# Rootkit 部署指南

本文档提供了在不同Linux发行版上部署rootkit的详细说明。

## ⚠️ 重要警告

**此rootkit仅用于教育和研究目的！**

- 请仅在您拥有完全控制权的系统上测试
- 不要在生产环境中使用
- 不要用于任何非法活动
- 使用前请确保了解相关法律法规

## 支持的Linux发行版

### 已测试的发行版

- Ubuntu 20.04/22.04 LTS
- CentOS 7/8
- RHEL 7/8/9
- Fedora 35+
- Debian 10/11
- Arch Linux

### 内核版本要求

- **推荐**: Linux 5.15.x
- **最低**: Linux 4.15+
- **最高**: Linux 6.x（可能需要适配）

## Ubuntu/Debian 部署

### 1. 环境准备

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装编译工具
sudo apt install -y build-essential

# 安装内核头文件
sudo apt install -y linux-headers-$(uname -r)

# 安装Git（如果需要）
sudo apt install -y git
```

### 2. 编译部署

```bash
# 克隆项目
git clone <repository-url>
cd rootkit

# 运行自动化测试脚本
./test_compile.sh

# 或者手动编译
make clean && make
```

### 3. 加载测试

```bash
# 加载内核模块
sudo insmod rootkit.ko

# 验证加载
lsmod | grep rootkit

# 使用控制程序
sudo ./control

# 卸载模块
sudo rmmod rootkit
```

## CentOS/RHEL 部署

### 1. 环境准备

```bash
# CentOS 7
sudo yum groupinstall -y "Development Tools"
sudo yum install -y kernel-devel kernel-headers

# CentOS 8+ / RHEL 8+
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y kernel-devel kernel-headers

# 确保内核版本匹配
sudo yum install -y kernel-devel-$(uname -r)
# 或
sudo dnf install -y kernel-devel-$(uname -r)
```

### 2. 编译部署

```bash
# 克隆项目
git clone <repository-url>
cd rootkit

# 运行测试脚本
./test_compile.sh
```

## Fedora 部署

### 1. 环境准备

```bash
# 安装编译工具
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y kernel-devel kernel-headers

# 安装当前内核的开发包
sudo dnf install -y kernel-devel-$(uname -r)
```

### 2. 编译部署

```bash
# 克隆项目
git clone <repository-url>
cd rootkit

# 运行测试脚本
./test_compile.sh
```

## Arch Linux 部署

### 1. 环境准备

```bash
# 安装编译工具
sudo pacman -S base-devel

# 安装内核头文件
sudo pacman -S linux-headers

# 如果使用LTS内核
sudo pacman -S linux-lts-headers
```

### 2. 编译部署

```bash
# 克隆项目
git clone <repository-url>
cd rootkit

# 运行测试脚本
./test_compile.sh
```

## 虚拟机部署建议

### VMware/VirtualBox

1. **创建Linux虚拟机**
   - 分配至少2GB内存
   - 20GB硬盘空间
   - 启用虚拟化功能

2. **安装Linux发行版**
   - 推荐Ubuntu 22.04 LTS
   - 安装时选择"最小安装"
   - 启用SSH服务（可选）

3. **配置开发环境**
   ```bash
   # 安装必要工具
   sudo apt update
   sudo apt install -y build-essential linux-headers-$(uname -r) git vim
   
   # 克隆项目
   git clone <repository-url>
   cd rootkit
   
   # 测试编译
   ./test_compile.sh
   ```

### Docker容器（不推荐）

⚠️ **注意**: Docker容器通常不支持加载内核模块，因为容器与宿主机共享内核。如果需要在容器中开发，可以：

1. 使用特权容器模式
2. 挂载宿主机的内核头文件
3. 仅用于编译，不用于加载测试

```bash
# 创建特权容器（仅用于编译测试）
docker run --privileged -v /lib/modules:/lib/modules:ro -v $(pwd):/workspace ubuntu:22.04
```

## 常见问题排查

### 1. 编译错误

**错误**: `fatal error: linux/module.h: No such file or directory`

**解决**: 安装内核头文件
```bash
# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install kernel-devel
```

### 2. 版本不匹配

**错误**: `version magic` 不匹配

**解决**: 确保内核头文件版本与运行内核一致
```bash
# 检查内核版本
uname -r

# 检查头文件版本
ls /lib/modules/

# 重新安装匹配的头文件
sudo apt install linux-headers-$(uname -r)
```

### 3. 权限问题

**错误**: `Operation not permitted`

**解决**: 使用sudo权限
```bash
sudo insmod rootkit.ko
sudo ./control
sudo rmmod rootkit
```

### 4. 模块加载失败

**错误**: `Invalid module format`

**解决**: 检查内核配置和编译环境
```bash
# 检查内核配置
zcat /proc/config.gz | grep CONFIG_MODULE

# 重新编译
make clean && make
```

## 安全注意事项

1. **测试环境隔离**
   - 使用虚拟机或容器
   - 不要在重要系统上测试
   - 定期备份测试环境

2. **网络隔离**
   - 断开网络连接进行测试
   - 使用内网环境
   - 监控网络活动

3. **日志监控**
   - 监控系统日志
   - 检查内核消息
   - 记录测试活动

4. **及时清理**
   - 测试完成后立即卸载模块
   - 清理编译文件
   - 删除敏感数据

## 技术支持

如果在部署过程中遇到问题，请：

1. 首先运行 `./test_compile.sh` 进行环境检查
2. 查看编译错误信息
3. 检查内核版本兼容性
4. 参考本文档的常见问题部分

---

**再次提醒**: 此rootkit仅用于教育和研究目的，请遵守相关法律法规，在合法合规的前提下使用。