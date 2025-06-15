// 1. disp头文件
#include <stdio.h>
#include <stdlib.h>  // 使用 system()
// ANSI 颜色代码
#define COLOR_MAIN   "\033[1;35m"
#define COLOR_NAME   "\033[1;36m"
#define COLOR_PURPLE     "\x1b[38;5;141m"  // #a277ff (亮紫)
#define COLOR_TEAL       "\x1b[38;5;85m"   // #61ffca (蓝绿)
#define COLOR_ORANGE     "\x1b[38;5;222m"  // #ffca85 (浅橙)
#define COLOR_GRAY_WHITE "\x1b[38;5;255m"  // #edecee (灰白)
#define COLOR_PINK_PURPLE "\x1b[38;5;213m" // #f694ff (粉紫)
#define COLOR_LIGHT_BLUE "\x1b[38;5;153m"  //蓝色
#define COLOR_RESET      "\x1b[0m"         // 重置颜色

#define CO_OPT1 COLOR_GRAY_WHITE  // 括号颜色
#define CO_OPT2 COLOR_PURPLE      // 数字颜色
#define CO_OPT3 COLOR_ORANGE      // 文本颜色
#define CO_OPT4 COLOR_PURPLE                                                                 
#define CO_OPT5 COLOR_LIGHT_BLUE
#define CO_OPT6 COLOR_PINK_PURPLE
#define COLOR_WARNING COLOR_PINK_PURPLE

// 清屏宏 (跨平台)
#ifdef _WIN32
#define CLEAR_SCREEN "cls"
#else
#define CLEAR_SCREEN "clear"
#endif
// 检查返回值是否是错误标记,若是则打印msg和错误信息
#define ERROR_CHECK(ret, error_flag, msg) \
    do { \
        if ((ret) == (error_flag)) { \
            perror(msg); \
            exit(1); \
        } \
    } while (0)

void disp_header();

// 打印左侧DIR栏和命令行提示
#define DIR_LABEL "DIR"
#define DIR_LABEL_WIDTH 8

void disp_prompt(const char* user, const char* cwd);

//帮助手册
void disp_help();

//展示当前目录
void disp_pwd();

void disp_end();
//2. client_init头文件
char token[1024];
int sock_fd;//全局变量sockfd，不然很多函数都要加参填参很麻烦

//3. tlv头文件
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct tlv_s {
    uint8_t  type;   // 主类别 (1字节)
    uint16_t len;    // 数据长度 (2字节)
    uint8_t  value[]; // 柔性数组
} tlv_t;



typedef enum {
    /*---- 命令类别 (COMMAND 0x0*) ----*/
    CMD_SHORT_CD    = 0x00,   // 短的cd,不带数据
    CMD_SHORT_LS    = 0x01,   // 短的ls,不带数据
    CMD_LONG_CD     = 0x02,   // 长的cd,携带路径
    CMD_MKDIR       = 0x03,   // 列出文件（注意：原表描述与名称不一致）
    CMD_REMOVE      = 0x04,   // 删除文件

    /*---- 认证类别 (AUTH 0x1*) ----*/
    AUTH_REGISTER   = 0x10,   // 用户注册
    AUTH_LOGIN      = 0x11,   // 用户登录
    AUTH_LOGOUT     = 0x12,   // 用户登出
    AUTH_TOKEN      = 0x13,   // 发送token
    AUTH_TOK_REF    = 0x14,   // Token刷新
    AUTH_SALT       = 0x15,   // 盐值

    /*---- 文件传输类别 (TRANS 0x2*) ----*/
    CMD_UPLOAD              = 0x20,  // 上传
    CMD_DOWNLOAD            = 0x21,  // 下载
    TRANS_META              = 0x22,  // 文件元数据
    TRANS_TOKEN             = 0x23,  // 客户端TOKEN下载：子线程
    TRANS_CHUNK             = 0x24,  // 服务端分块包
    TRANS_TO_CHECK_POINT    = 0x25,  // 需要检查断点
    TANS_BREAKPOINT_OK      = 0x26,  // 正确的断点
    TANS_BREAKPOINT_ERR     = 0x27,  // 错误的断点
    TANS_ENABLE_UPLOAD      = 0x28,  // 允许上传
    TANS_SMALL_DOWNLOAD     = 0x29,  // 小文件下载：主线程
    TANS_ENABLE             = 0x2F,  // 允许发送文件（调整为0x2F解决冲突）

    /*---- 响应类别 (RESPONSE 0x3*) ----*/
    SUCCESS_REGIS       = 0x30,  // 注册成功
    SUCCESS_LOGIN       = 0x31,  // 登录成功
    INVALID_DIR         = 0x32,  // cd失败，目录不合法
    CMD_SUCCESS         = 0x33,  // 命令成功
    MKDIR_FAILED        = 0x34,  // 创建目录失败
    REMOVE_DIR_FAILED   = 0x36,  // 删除目录失败
    RETRANS             = 0x38,  // 重新传输
    TRANS_SUCCESS       = 0x39,  // 传输成功

    /*---- 错误类别 (ERROR 0x4*) ----*/
    ERR_NAME_CONFLICT       = 0x40,  // 重名错误
    ERR_PASSWORD_INVALID   = 0x41,  // 密码错误
    ERR_USER_NOT_FOUND     = 0x42,  // 未找到用户名
    ERR_TRANS_ARGS         = 0x43,  // 传输参数错误
    ERR_FILE               = 0x44,  // 文件操作错误
    ERR_NET                = 0x45,  // 网络错误
    ERR_SER                = 0x46   // 服务端内部错误（新增）
} tlvType;


//4. handle头文件
#include <ctype.h>
int handle_usr(int type);
int is_path(char* buf);
void handle_cmd(char* command);
void handle_client(int sockfd);


//5. usr头文件
char usr_name[128];//用户
char cwd[1024];
int usr_register();
int usr_login();
void usr_exit();

//6. auth头文件
void salted_hash(const char* password, char* salt, char* hash);




//7. cmd头文件

void cmd_ls(int sock_fd);
void cmd_cd_long(int sock_fd, const char* path);
void cmd_cd_short(int sock_fd);


// 8.初始化
int client_init(const char* filename, char* token_out, size_t token_out_size,const char* log_path);


// 9.log 头文件
#include <time.h>
#include <stdarg.h>
static FILE* log_file = NULL;
// 初始化日志系统
void init_logger(const char* log_file_path);
// 记录连接信息
void log_connection(int client_socket);
// 记录操作信息
void log_operation(const char* operation,...);
// 记录错误信息（带文件和行号）
void log_error(const char* file, int line, const char* message,...);
// 关闭日志系统
void close_logger();

// 10.校验码

//文件验证
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define SHA256_BLOCK_SIZE 32

// SHA256上下文结构
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;
// 循环右移函数
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))

// SHA256辅助宏
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

#define BUFFER_SIZE 4096

// 常量数组
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
void sha256_transform(SHA256_CTX* ctx, const uint8_t data[]);
void sha256_transform(SHA256_CTX* ctx, const uint8_t data[]);
void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX* ctx, uint8_t hash[]);
int sha256_calc_range(const char* filename, size_t offset, size_t len, char* out_str);



int main() {

    // TCP 连接
    sock_fd=client_init("./client.config",token,sizeof(token),"./log");
    
    
    //展示UI
    disp_header();

    int type;
    scanf("%d", &type);
    handle_usr(type);

    system(CLEAR_SCREEN);
    while (1)
    {
        char command[128] = { 0 };
        //每次展示prompt
        disp_prompt(usr_name, cwd);
        scanf("%s", command);
        //handle_cmd(command);
    }
    disp_end();
}


//1. disp函数

void disp_header() {
    system(CLEAR_SCREEN);
    printf("\n");
    printf(
        COLOR_TEAL
        "\t__        __                              _                     ____    _         _    \n"
        "\t \\ \\      / /   __ _   _ __     __ _    __| |   __ _    ___     |  _ \\  (_)  ___  | | __\n"
        "\t  \\ \\ /\\ / /   / _` | | '_ \\   / _` |  / _` |  / _` |  / _ \\    | | | | | | / __| | |/ /\n"
        "\t   \\ V  V /   | (_| | | | | | | (_| | | (_| | | (_| | | (_) |   | |_| | | | \\__ \\ |   < \n"
        "\t    \\_/\\_/     \\__,_| |_| |_|  \\__, |  \\__,_|  \\__,_|  \\___/    |____/  |_| |___/ |_|\\_\\\n"
        "\t                               |___/\n"
        COLOR_RESET
    );
    printf(COLOR_TEAL "\n\tYour files, everywhere.\n" COLOR_RESET);
    printf("\n");
    printf("\n");

    printf(CO_OPT1 "\t[" CO_OPT2 "0" CO_OPT1 "]" CO_OPT3 "  新用户注册\t" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT2 "1" CO_OPT1 "]" CO_OPT3 "  用户登录\t" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT2 "2" CO_OPT1 "]" CO_OPT3 "  忘记密码\t" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT2 "3" CO_OPT1 "]" CO_OPT3 "  退出系统\t\n" COLOR_RESET);
    printf(
        COLOR_GRAY_WHITE "\n"
        "\t---------------------------------------------------------\n" COLOR_RESET
        COLOR_ORANGE          "\t* " COLOR_TEAL"今日推荐：" COLOR_ORANGE "新用户注册即送 5GB 免费存储空间!\n"
        "\t* " COLOR_TEAL "系统状态：" COLOR_ORANGE "正常运行中,快去备份你的文件吧!\n"
        "\t* " COLOR_TEAL "最新动态：" COLOR_ORANGE "客户端 v5.2.0 即将发布，" COLOR_PINK_PURPLE "新增6元首充礼包!\n"
        COLOR_GRAY_WHITE "\t---------------------------------------------------------\n\n"
    );
    printf(COLOR_WARNING "\t>>请选择操作编号 [" COLOR_PURPLE "0-3" COLOR_WARNING "]:" COLOR_RESET "   ");
    fflush(stdout);
}
void disp_help() {
    printf(COLOR_PINK_PURPLE "\tHelp\n\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "0" CO_OPT1 "]" CO_OPT5 "   <cd>" COLOR_RESET "\t" CO_OPT6"切换当前工作目录\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "1" CO_OPT1 "]" CO_OPT5 "   <ls>" COLOR_RESET "\t" CO_OPT6 "列出当前目录下所有文件和目录\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "2" CO_OPT1 "]" CO_OPT5 "   <pwd>" COLOR_RESET "\t" CO_OPT6 "显示当前虚拟工作目录\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "3" CO_OPT1 "]" CO_OPT5 "   <mkdir>" COLOR_RESET "\t" CO_OPT6 "创建新目录\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "4" CO_OPT1 "]" CO_OPT5 "   <rmdir>" COLOR_RESET "\t" CO_OPT6 "删除空目录\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "5" CO_OPT1 "]" CO_OPT5 "   <rm>" COLOR_RESET "\t" CO_OPT6 "删除文件\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "6" CO_OPT1 "]" CO_OPT5 "   <puts>" COLOR_RESET "\t" CO_OPT6 "上传本地文件到网盘\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "7" CO_OPT1 "]" CO_OPT5 "   <gets>" COLOR_RESET "\t" CO_OPT6 "从网盘下载文件到本地\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "8" CO_OPT1 "]" CO_OPT5 "   <help>" COLOR_RESET "\t" CO_OPT6 "显示所有可用指令及功能说明\n" COLOR_RESET);
    printf(CO_OPT1 "\t[" CO_OPT4 "9" CO_OPT1 "]" CO_OPT5 "   <q>" COLOR_RESET "\t" CO_OPT6 "退出系统\n" COLOR_RESET);
    fflush(stdout);
}

void disp_prompt(const char* user, const char* cwdir) {
    printf("\033[2J\033[H");
    // 左侧大写DIR
    printf("\033[1;34m%-*s\033[0m", DIR_LABEL_WIDTH, DIR_LABEL); // 蓝色高亮
    printf("  @%s: %s\n", user, cwdir);
    printf("%-*s", DIR_LABEL_WIDTH, ""); // 补齐左栏
    fflush(stdout);
}

void disp_end() {
    // 1. 显示小组信息和感谢语
    printf(COLOR_NAME "\n\t小组名称：bug.cpp\n" COLOR_RESET);
    printf(COLOR_NAME "\t感谢全体成员的努力！\n\n" COLOR_RESET);
    fflush(stdout);

    // 2. 暂停2秒
    usleep(2000000);

    // 3. 上浮清屏动画（快速消失）
    for (int slide = 0; slide < 8; ++slide) {
        printf("\033[2J\033[H"); // 清屏并移动光标到左上角
        if (slide < 2) printf(COLOR_NAME "\n\t小组名称：bug.cpp\n" COLOR_RESET);
        if (slide < 4) printf(COLOR_NAME "\t感谢全体成员的努力！\n" COLOR_RESET);
        fflush(stdout);
        usleep(60000); // 0.06秒
    }

    // 4. 显示艺术字图案
    printf(COLOR_MAIN);
    printf("\t⣺⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡅⡅⡅⡝⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⡅⡀⡀⣺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠦⡀⡀⡀⡀⡀⢕⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⡝⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⡅⡀⡠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⢹⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⢻⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡅⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⡅⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡅⣺⣺⣺⣺⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⠙⡅⡀⡀⣿⣿⣿⣿⣿⣿⣿⠗⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⡅⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡽⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⡅⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⠙⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⡅⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡅⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⠙⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⡅⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⢿⡀⡅⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣿⣿⣺⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⡅⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⢹⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣿⣿⣿⣿⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣺⣺⣺⣿⣺⡀⡀⣿⣺⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⡅⣺⣺⣺⣺⣺⣺⣺⡅⡀⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⢕⣿⣿⡀⡀⡀⡀⣿⢻⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⡅⠊⡀⡀⡀⠊⡀⡀⡀⡀⡅⡅⣺⣺⣺⣺⣺⣺⣺⣺⣺⠊⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⠧⣿⡀⡀⡀⡀⡀⣺⣿⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⣿⣿⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⢻⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣿\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⣹⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣿⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣯⣿⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣿⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⡀⣿⣺⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⠊⡀⡀⡀⡀⡮⣿⣿⣿⡀⡀⡀⡀⣿⣿⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⣿⡀â[Mab+⣿⣿⣿⣺⣺⣺⣺⣺⣿⣿⡀⡀⣿⣺⣺⣺⣺⣺⣺\n");
    printf("\t⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⣿⣿⣿⣿⣺⣺⣺⣺⣺⣺⣺⣺⣺⣺⣿⣿⣿⣺⣺⣺⣺⣺⣺\n");
    printf(COLOR_RESET);

    usleep(2200000); // 停留2.2秒
}

void disp_pwd() { printf("pwd: 当前路径为 /fake/path\n"); }
//2. tlv函数

// 创建TLV包
tlv_t* tlv_create(uint8_t type, const void* data, uint16_t len) {
    // 检查参数有效性
    if (len > 0 && data == NULL) {
        fprintf(stderr, "错误: 非空长度需要有效数据指针\n");
        return NULL;
    }

    // 计算总内存大小（结构体 + 数据区）
    size_t total_size = sizeof(tlv_t) + len;
    tlv_t* tlv = (tlv_t*)malloc(total_size);
    if (tlv == NULL) {
        perror("内存分配失败");
        return NULL;
    }

    // 填充TLV头部
    tlv->type = type;
    tlv->len = len;

    // 如果有数据则拷贝
    if (len > 0 && data != NULL) {
        memcpy(tlv->value, data, len);
    }

    return tlv;
}

// 释放TLV包
void tlv_free(tlv_t* tlv) {
    if (tlv) {
        free(tlv);
    }
}

// 发送TLV包
int tlv_send(int sockfd, tlv_t* tlv) {
    // 发送头部 (type + len)
    uint8_t header[3];
    header[0] = tlv->type;
    *(uint16_t*)(header + 1) = htons(tlv->len); // 网络字节序

    if (send(sockfd, header, 3, 0) != 3) {
        return -1; // 发送头部失败
    }

    // 发送数据体 (如果有)
    if (tlv->len > 0 && send(sockfd, tlv->value, tlv->len, 0) != tlv->len) {
        return -1; // 发送数据失败
    }
    return 0;
}

// 接收TLV包
tlv_t* tlv_recv(int sockfd) {
    // 接收头部
    uint8_t header[3];
    if (recv(sockfd, header, 3, MSG_WAITALL) != 3) {
        return NULL; // 接收头部失败
    }

    // 解析头部
    uint8_t type = header[0];
    uint16_t len = ntohs(*(uint16_t*)(header + 1)); // 主机字节序

    // 创建TLV包
    tlv_t* tlv = (tlv_t*)malloc(sizeof(tlv_t) + len);
    if (!tlv) return NULL;

    tlv->type = type;
    tlv->len = len;

    // 接收数据体 (如果有)
    if (len > 0 && recv(sockfd, tlv->value, len, MSG_WAITALL) != len) {
        free(tlv);
        return NULL;
    }
    return tlv;
}



//3. handle函数


int handle_usr(int type)
{
    switch (type)
    {
        case 0:
            usr_register();
            break;
        case 1:
            usr_login();
            break;
        case 2:
            usr_exit();
            break;
        case 3:
            usr_exit();
            break;
        default:
            printf("无效的操作编号！\n");
            break;
    }
    return 0;
}

int is_path(char* buf) {
    // 空指针或空字符串检查
    if (!buf || *buf == '\0') return 0;

    size_t len = strlen(buf);

    // 基础长度检查（避免超长路径）
    if (len > 4096) return 0;

    // 特殊路径检查：当前目录(".")或上级目录("..")
    if (strcmp(buf, ".") == 0 || strcmp(buf, "..") == 0) return 1;

    // 遍历检查每个字符
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = buf[i];

        // 禁止控制字符(0-31)和删除符(127)
        if (c < 32 || c == 127) return 0;

        // 禁止Windows非法字符（跨平台兼容考虑）
        if (strchr("<>:\"|?*", c)) {
            // 允许盘符冒号(如 C:)
            if (c == ':' && i == 1 && isalpha(buf[0])) continue;
            return 0;
        }
    }

    // 禁止首尾空格（文件系统常见限制）
    if (isspace(buf[0]) || isspace(buf[len - 1])) return 0;

    return 1;
}


void handle_cmd(char* command) {
    char tmp[1024] = { 0 };
    char* cmd, * p1, * p2;
    int cnt_paras = 0;

    // 去掉末尾换行和空格
    size_t len = strlen(command);
    while (len > 0 && (command[len - 1] == '\n' || command[len - 1] == '\r')) len--;
    strncpy(tmp, command, len);
    tmp[len] = '\0';

    //命令限定一个参数
    cmd = strtok(tmp, " ");
    if (!cmd) return;

    p1 = strtok(NULL, " ");
    if (p1)
    {
        /*
        第一个参数只能为路径，先排除奇怪的输入
        这里不检查路径是否合法
        */
        if (!is_path(p1))
        {
            printf("\t参数错误\n");
            return;
        }
        ++cnt_paras;
    }

    p2 = strtok(NULL, " ");
    //输入了两个参数：打印并退出
    if (p1)
    {
        printf("\t参数错误\n");
        return;
    }

    //进入判断逻辑能保证只有1或0个参数
    if (strcmp(cmd, "cd") == 0) {
        if (0 == cnt_paras)cmd_cd_short(sock_fd);
        else if (1 == cnt_paras)cmd_cd_long(sock_fd, p1);
    }
    else if (strcmp(cmd, "ls") == 0) {
        if (1 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
        cmd_ls(sock_fd);

    }
    else if (strcmp(cmd, "gets") == 0) {
        if (0 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }

        //发送包给服务端检查路径
        //收到包后
       /* if (tlv->tyep == )
[Maf+[Maf+[Maf+[Maf+[Maf+        {
            if (0 == cnt_paras)
            {
                printf("\t路径不存在\n");
                return;
            }
        }*/

        //收文件部分
    }
    else if (strcmp(cmd, "puts") == 0) {
        if (0 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }

        //发送包给服务端检查路径
        //收到包后
       /* if (tlv->tyep == )
        {
            if (0 == cnt_paras)
            {
                printf("\t路径不存在\n");
                return;
            }
        }*/

        //发文件部分
    }
    else if (strcmp(cmd, "rm") == 0) {
        if (0 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
    }
    else if (strcmp(cmd, "mkdir") == 0) {
        if (0 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
    }
    else if (strcmp(cmd, "rmdir") == 0) {
        if (0 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
    }
    else if (strcmp(cmd, "pwd") == 0) {
        if (1 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
        disp_pwd();
    }
    else if (strcmp(cmd, "help") == 0) {
        if (1 == cnt_paras)
        {
            printf("\t参数错误\n");
            return;
        }
        disp_help();
    }
    else if (strcmp(cmd, "ftp") == 0) {
        if (1 == cnt_paras)
        {
            printf("\t参[Mak-数错误\n");
            return;
        }
        disp_help();
    }
    //未定义命令，无视
    else {
        printf("\t命令错误\n");
        return;
    }
}



//4. usr函数

int usr_register() {
    char salt[1024] = { 0 };
    char crptpswd[512] = { 0 };
    while (1)
    {
        char pswd1[1024] = { 0 };
        char pswd2[1024] = { 0 };
        fflush(stdout);
        // 1. 输入用户名，判断是否重名
        while (1)
        {
            memset(usr_name, 0, sizeof(usr_name));
            printf("\t用户名: ");
            scanf("%127s", usr_name);

            //发送用户名
            tlv_t* t = tlv_create(AUTH_REGISTER, usr_name, strlen(usr_name) + 1);
            tlv_send(sock_fd, t);
            tlv_free(t);

            //收服务端的响应
            t = tlv_recv(sock_fd);

            //正确，保存盐值退出
            if (AUTH_SALT == t->type && t->len > 0)//收到的包不对也让用户重新输入
            {
                memcpy(salt, t->value, sizeof(salt) - 1);
                salt[strlen(salt) + 1] = '\0'; // 确保字符串终止
                tlv_free(t);
                break;
            }
            //错误继续
            else if (ERR_NAME_CONFLICT == t->type)
            {
                printf("\t错误：用户名重复！\n");
                tlv_free(t);
            }
        }

        //清理输入缓冲区
        int c;
        while ((c = getchar()) != '\n' && c != EOF);


        while (1)
        {
            // 2. 输入两次密码并判断
            char* p1 = getpass("\t密码：  "); strncpy(pswd1, p1, sizeof(pswd1) - 1);
            char* p2 = getpass("\t再次输入密码：  ");
            strncpy(pswd2, p2, sizeof(pswd2) - 1);
            if (strcmp(pswd1, pswd2) != 0)
            {
                printf("\t输入错误！\n");
            }
            else//两次输入一致
            {
                //加盐,发送密码
                salted_hash(p1, salt, crptpswd);
                tlv_t* t = tlv_create(AUTH_REGISTER, crptpswd, strlen(crptpswd) + 1);
                tlv_send(sock_fd, t);
                tlv_free(t);
                t=NULL;
                
                //收服务端的响应
                t = tlv_recv(sock_fd);
                
                if (AUTH_TOKEN == t->type) 
                {
                    if (t->len < sizeof(token)) {
                        memset(token, 0, sizeof(token));
                        memcpy(token, t->value, t->len);
                        token[t->len] = '\0'; // 添加字符串终止符
                        memset(cwd, 0, sizeof(cwd));
                        strncpy(cwd, "~/", 3);
                        tlv_free(t);
                        printf("\t注册成功！欢迎你，%s。\n", usr_name);
                        sleep(1);
                        return 0;
                    } else {
                        printf("接收到的令牌过长，无法存储！\n");
                        tlv_free(t);
                        return -1; // 返回错误码
                    }
                }
            }
        }
    }
}



int usr_login() {

    char salt[1024] = { 0 };
    char crptpswd[512] = { 0 };
    while (1)
    {

        char pswd1[1024] = { 0 };
        char pswd2[1024] = { 0 };

        fflush(stdout);

        // 1. 输入用户名，判断是否重名
        while (1)
        {     
            memset(usr_name, 0, sizeof(usr_name));
            printf("\t用户名: ");
            scanf("%127s", usr_name);

            //发送用户名
            tlv_t* t = tlv_create(AUTH_LOGIN, usr_name, strlen(usr_name) + 1);
            tlv_send(sock_fd, t);
            tlv_free(t);

            //收服务端的响应
            t = tlv_recv(sock_fd);

            //正确，保存盐值break
            if (AUTH_SALT == t->type && t->len > 0)//收到的包不对也让用户重新输入
            {
                memcpy(salt, t->value, sizeof(salt) - 1);
                salt[strlen(salt) + 1] = '\0'; // 确保字符串终止
                tlv_free(t);
                break;
            }
            //错误继续输入
            else if (ERR_USER_NOT_FOUND == t->type)
            {
                printf("\t错误：用户名不存在！\n");
                tlv_free(t);
            }
        }

        //清理输入缓冲区
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        while (1)
        {
            // 2. 输入两次密码并判断
            char* p1 = getpass("\t密码：  "); strncpy(pswd1, p1, sizeof(pswd1) - 1);
            char* p2 = getpass("\t再次输入密码：  ");
            strncpy(pswd2, p2, sizeof(pswd2) - 1);
            if (strcmp(pswd1, pswd2) != 0)
            {
                printf("\t输入错误！\n");
            }
            else
            {
                //加盐,发送密码
                salted_hash(p1, salt, crptpswd);
                tlv_t* t = tlv_create(AUTH_REGISTER, crptpswd, strlen(crptpswd) + 1);
                tlv_send(sock_fd, t);
                tlv_free(t);

                //收服务端的响应
                t = tlv_recv(sock_fd);
                if (AUTH_TOKEN == t->type)
                {
                    //保存token的内容，修改cwd
                    memset(token, 0, sizeof(token));
                    memcpy(token, t->value, t->len);
                    memset(cwd, 0, sizeof(cwd));
                    strncpy(cwd, "~/", 3);

                    tlv_free(t);
                    printf("\t登录成功！欢迎你，%s。\n", usr_name);
                    sleep(1);
                    return 0;
                }
                else if (ERR_PASSWORD_INVALID == t->type)
                {
                    printf("\t密码错误！\n");
                    tlv_free(t);
                }
            }
        }
    }
}


void usr_exit()
{
    char choice;
    printf(COLOR_TEAL "\n\t确认退出网盘客户端吗？(y/n): " COLOR_RESET);
    fflush(stdout);

    // 读取用户输入，只接受y/n
    while (1) {
        choice = getchar();
        if (choice == 'y' || choice == 'Y') {
            break;
        }
        else if (choice == 'n' || choice == 'N') {
            printf(COLOR_TEAL "\t已取消退出。\n" COLOR_RESET);
            return;
        }
        else if (choice == '\n') {
            continue;
        }
        else {
            printf(COLOR_TEAL "\t请输入 y 或 n: " COLOR_RESET);
            fflush(stdout);
            // 清除多余输入
            while (getchar() != '\n');
        }
    }

    // 退出动画
    printf(COLOR_PINK_PURPLE "\n\t正在安全退出网盘客户端" COLOR_RESET);
    fflush(stdout);
    for (int i = 0; i < 6; ++i) {
        usleep(200000); // 0.2秒
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    disp_end();
    printf(COLOR_PINK_PURPLE "\t再见！\n" COLOR_RESET);
    exit(0);
}



//5. auth函数(加盐，sha256的信息等)
void salted_hash(const char* password, char* salt, char* hash)
{
    char* crypt_result = crypt(password, salt);
    if (crypt_result) {
        strcpy(hash, crypt_result);
    }
    else {
        hash[0] = '\0';
    }
}



//6.cmd函数
// cd无参数：切换到根目录
void cmd_cd_short(int sock_fd) {
    // 发送CMD_SHORT_CD包，空包
    tlv_t* t = tlv_create(CMD_SHORT_CD, NULL, 0);
    if (!t) return;
    tlv_send(sock_fd, t);
    tlv_free(t);
    t = NULL;
    // 接收服务器响应
    t = tlv_recv(sock_fd);

    //著名程序员泥鳅曾经说过，没有消息就是最好的消息
    if (t->type == CMD_SUCCESS)
    {

    }
    tlv_free(t);
}


// cd带路径：切换到指定路径
void cmd_cd_long(int sock_fd, const char* path) {
    if (!path) return;
    tlv_t* t = tlv_create(CMD_LONG_CD, path, strlen(path) + 1);
    if (!t) return;
    tlv_send(sock_fd, t);
    tlv_free(t);
    t = NULL;

    t = tlv_recv(sock_fd);
    if (t->type == INVALID_DIR) {
        printf("\t参数错误\n");
    }
    //著名程序员泥鳅曾经说过，没有消息就是最好的消息
    else if (t->type == CMD_SUCCESS)
    {

    }
    tlv_free(t);
}

// ls命令
void cmd_ls(int sock_fd) {
    // 发送CMD_SHORT_LS包，无数据
    tlv_t* t = tlv_create(CMD_SHORT_LS, NULL, 0);
    if (!t) return;
    tlv_send(sock_fd, t);
    tlv_free(t);
    t = NULL;

    // 接收服务器响应
    t = tlv_recv(sock_fd);
    if (!t) {
        printf("\t网络错误或服务器无响应\n");
        return;
    }

    if (t->type == CMD_SUCCESS)
    {
        //空目录情况
        if (t->len == 0)
        {
            printf("\t该目录下无文件或子目录\n");
        }
        else
        {
            // 解析服务器返回内容[Mat3[Mat3[Mat3，#开头为目录，$开头为文件，多个名称以\0分隔
            //展示目录，alpha测试暂时不重要
            char* p = (char*)t->value;
            while (*p) {
                if (*p == '#') {
                    printf("[DIR] %s\n[Mau3[Mau3[Mau2[Mau2", p + 1);
                }
                else if (*p == '$') {
                    printf("      %s\n", p + 1);
                }
                p += strlen(p) + 1;
            }
        }
    }
    tlv_free(t);
}
// 8. 初始化
int client_init(const char* filename, char* token_out, size_t token_out_size,const char* log_path) {
    /*
    client.config格式：
    ip:172.28.138.3
    port:23456
    token:
    host:localhost
*/
    FILE* fp = fopen(filename, "r");
    ERROR_CHECK(fp, NULL, "fopen client.config failed");
    init_logger(log_path);
    char ip[16] = { 0 };
    char port[6] = { 0 };
    char buf[1024] = { 0 };

    // 解析ip
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        fprintf(stderr, "Failed to read IP line\n");
        return -1;
    }
    char* p = strchr(buf, ':');
    if (p && p[1]) {
        char* nl = strchr(p + 1, '\n');
        if (nl) *nl = '\0';
        strncpy(ip, p + 1, sizeof(ip) - 1);
    }

    // 解析port
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        fprintf(stderr, "Failed to read Port line\n");
        return -1;
    }
    p = strchr(buf, ':');
    if (p && p[1]) {
        char* beg = p + 1;
        char* end = beg + strspn(beg, "0123456789");
        size_t len = end - beg;
        if (len > 0 && len <= sizeof(port) - 1) {
            memcpy(port, beg, len);
            port[len] = '\0';
        }
        else {
            fclose(fp);
            fprintf(stderr, "Invalid port format\n");
            return -1;
        }
    }

    // 解析token（第三行），允许为空
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        fprintf(stderr, "Failed to read Token line\n");
        return -1;
    }
    p = strchr(buf, ':');
    if (p) {
        // p后可能什么都没有
        char* token_start = p + 1;
        // 移除换行
        char* nl = strchr(token_start, '\n');
        if (nl) *nl = '\0';
        // 跳过前导空白
        while (*token_start == ' ' || *token_start == '\t') ++token_start;
        // 允许token为空字符串
        strncpy(token_out, token_start, token_out_size - 1);
        token_out[token_out_size - 1] = '\0';
    }
    else {
        // 没有冒号，token视为空
        if (token_out_size > 0) token_out[0] = '\0';
    }

    // 跳过host行（可选，有就跳，没有也不影响）
    fgets(buf, sizeof(buf), fp);
    fclose(fp);

    // 创建socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(port));
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    // 连接服务器
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    // 返回连接描述符
    return sockfd;
}
// 9.log函数
void init_logger(const char* log_file_path) {
    if (log_file != NULL) {
        fclose(log_file);
    }
    log_file = fopen(log_file_path, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
    }
}

void log_connection(int client_socket) {
    if (log_file == NULL) return;
    
    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_socket, (struct sockaddr *)&addr, &addr_size);
    char* client_ip = inet_ntoa(addr.sin_addr);
    
    fprintf(log_file, "[CONNECTION][%s] Client connected from: %s\n", time_str, client_ip);
    fflush(log_file);
}

/*void log_upload(const char* username, const char* filename, long size) {
    if (log_file == NULL) return;

    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[UPLOAD][%s] User: %s, File: %s, Size: %ld bytes\n",
            time_str, username, filename, size);
    fflush(log_file);
}
*/

/*
void log_download(const char* username, const char* filename, long size) {
    if (log_file == NULL) return;

    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[DOWNLOAD][%s] User: %s, File: %s, Size: %ld bytes\n",
            time_str, username, filename, size);
    fflush(log_file);
}
*/

void log_error(const char* file, int line, const char* message,...) {

    if (log_file == NULL) return;

    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[ERROR][%s] File: %s, Line: %d - ", time_str, file, line);

    va_list args;
    va_start(args, message);
    vfprintf(log_file, message, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
}

void close_logger() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

// 10.校验码

// SHA256转换函数
void sha256_transform(SHA256_CTX* ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// SHA256初始化
void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// SHA256数据更新
void sha256_update(SHA256_CTX* ctx, const uint8_t data[], size_t len) {
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// SHA256最终计算
void sha256_final(SHA256_CTX* ctx, uint8_t hash[]) {
    uint32_t i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

int sha256_calc_range(const char* filename, size_t offset, size_t len, char* out_str) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        perror("文件打开失败");
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("fseek失败");
        fclose(fp);
        return -1;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    unsigned char buf[BUFFER_SIZE];
    size_t bytes_to_read, bytes_read, total_read = 0;
    while (total_read < len) {
        bytes_to_read = (len - total_read) < BUFFER_SIZE ? (len - total_read) : BUFFER_SIZE;
        bytes_read = fread(buf, 1, bytes_to_read, fp);
        if (bytes_read == 0) break;
        sha256_update(&ctx, buf, bytes_read);
        total_read += bytes_read;
        if (bytes_read < bytes_to_read) break;
    }

    if (ferror(fp)) {
        perror("文件读取错误");
        fclose(fp);
        return -1;
    }

    unsigned char hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);

    fclose(fp);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(out_str + (i * 2), "%02x", hash[i]);
    }
    out_str[SHA256_BLOCK_SIZE * 2] = '\0';

    return 0;
}
