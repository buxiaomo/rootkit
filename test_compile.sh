#!/bin/bash

# Rootkit编译测试脚本
# 此脚本用于在Linux环境下测试编译流程

echo "=== Rootkit编译环境检查 ==="

# 检查操作系统
echo "检查操作系统..."
OS=$(uname -s)
echo "操作系统: $OS"

if [ "$OS" != "Linux" ]; then
    echo "❌ 错误: 此rootkit只能在Linux系统上编译"
    echo "当前系统: $OS"
    echo "请在Linux虚拟机或服务器上运行此脚本"
    exit 1
fi

# 检查内核版本
echo "\n检查内核版本..."
KERNEL_VERSION=$(uname -r)
echo "内核版本: $KERNEL_VERSION"

# 检查内核头文件
echo "\n检查内核头文件..."
KERNEL_BUILD_DIR="/lib/modules/$KERNEL_VERSION/build"

if [ ! -d "$KERNEL_BUILD_DIR" ]; then
    echo "❌ 错误: 内核头文件未找到"
    echo "路径: $KERNEL_BUILD_DIR"
    echo "\n请安装内核头文件:"
    echo "Ubuntu/Debian: sudo apt install linux-headers-\$(uname -r)"
    echo "CentOS/RHEL:   sudo yum install kernel-devel kernel-headers"
    echo "Fedora:        sudo dnf install kernel-devel kernel-headers"
    echo "Arch Linux:    sudo pacman -S linux-headers"
    exit 1
fi

echo "✅ 内核头文件已安装: $KERNEL_BUILD_DIR"

# 检查编译工具
echo "\n检查编译工具..."

if ! command -v gcc &> /dev/null; then
    echo "❌ 错误: GCC编译器未安装"
    echo "请安装GCC: sudo apt install build-essential (Ubuntu/Debian)"
    exit 1
fi

GCC_VERSION=$(gcc --version | head -n1)
echo "✅ GCC编译器: $GCC_VERSION"

if ! command -v make &> /dev/null; then
    echo "❌ 错误: Make工具未安装"
    echo "请安装Make: sudo apt install build-essential (Ubuntu/Debian)"
    exit 1
fi

MAKE_VERSION=$(make --version | head -n1)
echo "✅ Make工具: $MAKE_VERSION"

# 检查权限
echo "\n检查权限..."
if [ "$EUID" -eq 0 ]; then
    echo "✅ 当前用户: root (可以加载/卸载内核模块)"
else
    echo "⚠️  当前用户: $(whoami) (需要sudo权限来加载/卸载模块)"
fi

echo "\n=== 环境检查完成 ==="
echo "\n开始编译rootkit..."

# 清理之前的编译文件
make clean 2>/dev/null

# 编译
if make; then
    echo "\n✅ 编译成功!"
    echo "\n生成的文件:"
    ls -la *.ko 2>/dev/null || echo "未找到.ko文件"
    
    echo "\n编译的用户态控制程序:"
    ls -la control 2>/dev/null || echo "未找到control程序"
    
    echo "\n使用方法:"
    echo "1. 加载模块: sudo insmod rootkit.ko"
    echo "2. 使用控制程序: sudo ./control"
    echo "3. 卸载模块: sudo rmmod rootkit"
    
    echo "\n⚠️  警告: 此rootkit仅用于教育和研究目的"
    echo "请在受控环境中测试，不要用于非法用途"
else
    echo "\n❌ 编译失败"
    echo "请检查错误信息并修复问题"
    exit 1
fi