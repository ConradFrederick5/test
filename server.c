#define MAX_TOKEN_SIZE 1024
//超时队列和session需要放前面
#include <sys/wait.h>
#include <mysql/mysql.h>
#include <limits.h>
#include <string.h>
#include "./include/l8w8jwt/include/l8w8jwt/decode.h" 
#include "./include/l8w8jwt/include/l8w8jwt/encode.h"
//11. l8w8jwt
int encode(char *key, char *usr_name, char *token);
int decode(char *key, char *usr_name, char *token);


//1.3超时队列
#define TIME_SLICE 30      // 超时时间轮长度，比如30s
#define MAX_FD 1024       // 支持的最大netfd/net_fd数（可按需调整）
#define SALT_LEN 16 // 盐值长度

typedef struct slot_node {
    int netfd;// 可用作fd或唯一id
    struct slot_node* next;
} slot_node_t;

typedef struct slot_list {
    slot_node_t* head;
    slot_node_t* tail;
    int size;
} slot_list_t;
typedef struct timeout_wheel {
    int timer;                  // 当前时间槽指针
    slot_list_t slots[TIME_SLICE]; // 时间轮
    int index[MAX_FD];         // netfd所在slot下标
} timeout_wheel_t;



void timeout_wheel_init(timeout_wheel_t* wheel);
void _remove_usr_from_slot(slot_list_t* slot, int netfd);
void timeout_wheel_touch(timeout_wheel_t* wheel, int netfd);
void timeout_wheel_tick(timeout_wheel_t* wheel, void (*on_timeout)(int netfd));

typedef struct Session_s {
    int netfd;
    char user_name[256];
    char virtual_cwd[PATH_MAX]; // 用户当前目录
    int cwd_id;                 // 当前目录id
    MYSQL* conn;
}Session_t;



//0.线程池
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <fcntl.h>
#define WORKER_NUM 3


// 任务类型枚举
typedef enum {
    TASK_UPLOAD,
    TASK_DOWNLOAD_SMALL,
    TASK_DOWNLOAD_LARGE
} task_type_t;

// 通用任务参数类型
typedef union {
    struct {
        int netfd;
        char filename[256];
    } upload;

    struct {
        int netfd;
        char filename[256];
    } download_small;

    struct {
        int netfd;
        char filename[256];
        off_t offset;
        size_t size;
        unsigned int chunk_index;
        unsigned int chunk_count;
    } download_large;
} task_param_t;

// 任务队列节点结构体
typedef struct node_s {
    task_type_t type;
    task_param_t param;
    struct node_s* pNext;
} node_t;

// 任务队列结构体
typedef struct {
    node_t* pFront;
    node_t* pRear;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int queueSize;
} taskQueue_t;

// 线程池结构体
typedef struct {
    pthread_t* threads;
    taskQueue_t taskQueue;
    int threadNum;
    int exitFlag;
} thread_pool_t;

int epoll_add(int epfd, int fd);
int epoll_del(int epfd, int fd);


int taskQueueInit(taskQueue_t* queue);
void enQueue(taskQueue_t* queue, task_type_t type, task_param_t* param);
node_t* deQueue(taskQueue_t* queue);
void* workerThread(void* arg);
int threadPoolInit(thread_pool_t* pool, int threadNum);
void threadPoolDestroy(thread_pool_t* pool);
void handler(int sig);
void close_fd_on_timeout(int fd);


// 1. server_init
void sig_handler1(int);
void sig_handler2(int);



typedef struct {
    int listen_fd;
    int epfd;
    int exitPipe[2];
    thread_pool_t threadPool;
    timeout_wheel_t timeout_wheel;
    MYSQL* conn;
    Session_t session[1024];
    int session_cnt;
    int hashmap[1024];
    //还有其他服务器需要的，后面都可以放在这里
} server_context_t;


int server_init(server_context_t* ctx, const char* conf_path,const char* log_path);

//1.0 session
#include <limits.h>


int session_insert(server_context_t* ctx,MYSQL* conn,const char* user_name,int netfd);
void session_release(Session_t* session);
int session_clean(server_context_t* ctx,int netfd);




// 1.2tcp初始化
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>


int tcpInit(const char* filename);








// 2. mysql



// 检查命令行参数数量是否符合预期
#define ARGS_CHECK(argc, expected) \
        do { \
                if ((argc) != (expected)) { \
                        fprintf(stderr, "args num error!\n"); \
                        exit(1); \
                } \
        } while (0)

// 检查返回值是否是错误标记,若是则打印msg和错误信息
#define ERROR_CHECK(ret, error_flag, msg) \
        do { \
                if ((ret) == (error_flag)) { \
                        perror(msg); \
                        exit(1); \
                } \
        } while (0)

#define THREAD_ERROR_CHECK(ret,msg){if(ret!=0){fprintf(stderr,"%s:%s",msg,strerror(ret));}}

// 检查返回值并打印详细错误信息（包含连接对象）
#define PSQL_ERROR_CHECK(ret,target, conn, msg) do { \
        if (ret == target) { \
                fprintf(stderr, "Error %s: %s\n", msg, mysql_error(conn)); \
                return EXIT_FAILURE; \
        } \
} while(0)

// 仅检查返回值并直接返回
#define SQL_ERROR_CHECK(ret,target, conn, msg) do { \
        if (ret != target) { \
                fprintf(stderr, "Error %s: %s\n", msg, mysql_error(conn)); \
                return EXIT_FAILURE; \
        } \
} while(0)


// 虚拟文件表结构体
typedef struct VirtualFileInfo_s{
    int id;
    char file_name[256];
    char user_name[256];
    int parent_id;
    char sha256[256];
    char file_type[16];
    char path[256];
    int link;
} VirtualFileInfo_t;

// 数据库连接
int db_connect(MYSQL** pconn);

// 往表中增加一条记录
int vf_insert(MYSQL *conn,const VirtualFileInfo_t *info);

// 查：根据虚拟路径和用户查 id
int vf_get_id_by_path_user(MYSQL *conn,const char *path, const char *user_name);

// 查：parent_id下所有文件/目录
VirtualFileInfo_t* vf_list_by_parent_id(MYSQL *conn,int parent_id, const char *user_name, int *count);

// 查：根据id查信息
int vf_get_info_by_id(MYSQL *conn,int id, VirtualFileInfo_t *info);

// 删：根据id删除（可递归目录）
int vf_delete_by_id(MYSQL *conn,int id);

// 查：同目录下是否已有同名
int vf_exist_in_dir(MYSQL *conn,int parent_id, const char *file_name, const char *user_name, const char *file_type);

// 用户注册默认插入函数
int vf_default_insert(MYSQL* conn,const char* user_name);

// 根据用户名查salt值和密文密码
int ui_get_salt_encrypt(MYSQL* conn,const char* user_name,char salt[],int salt_size,char crptpswd[],int crptpswd_size);




// 3. logger
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static FILE* log_file = NULL;

// 日志级别定义
typedef enum {
    LOG_LEVEL_CONNECTION,  // 连接日志
    LOG_LEVEL_OPERATION,   // 操作日志
    LOG_LEVEL_ERROR        // 错误日志
} LogLevel;

// 初始化日志系统
void init_logger(const char* log_file_path);

// 记录连接信息
void log_connection(int client_socket);


// 记录错误信息（带文件和行号）
void log_error(const char* file, int line, const char* message, ...);

// 关闭日志系统
void close_logger();

// 客户操作信息
void handle_client(int sockfd);
// 4. tlv
typedef struct tlv_s {
    uint8_t  type;  // 主类别 (1字节)
    uint16_t len;    // 数据长度 (2字节)
    uint8_t  value[];   // 柔性数组
} tlv_t;

typedef enum {
    // 命令类型: COMMAND (0x00-0x06)
    CMD_SHORT_CD = 0x00,   // 短的cd,不带数据
    CMD_SHORT_LS = 0x01,   // 短的ls,不带数据
    CMD_LONG_CD = 0x02,    // 长的cd,携带路径
    CMD_MKDIR = 0x03,      // 创建目录
    CMD_REMOVE = 0x04,     // 删除文件
    CMD_UPLOAD = 0x05,     // 上传
    CMD_DOWNLOAD = 0x06,   // 下载

    // 认证类型: AUTH (0x10-0x15)
    AUTH_REGISTER = 0x10,  // 用户注册
    AUTH_LOGIN = 0x11,     // 用户登录
    AUTH_LOGOUT = 0x12,    // 用户登出
    AUTH_TOKEN = 0x13,     // 发送token
    AUTH_TOK_REF = 0x14,   // Token刷新
    AUTH_SALT = 0x15,      // 盐值

    // 文件传输类型: TRANS (0x20-0x27)
    TRANS_META = 0x20,        // 文件元数据
    TRANS_TOKEN = 0x21,       // 客户端TOKEN下载
    TRANS_CHUNK = 0x22,       // 服务端分块包
    TRANS_TO_CHECK_POINT = 0x23,  // 需要检查断点
    TRANS_BREAKPOINT_OK = 0x24,   // 正确的断点
    TRANS_BREAKPOINT_ERR = 0x25,  // 错误的断点
    TRANS_ENABLE_UPLOAD = 0x26,   // 允许上传
    TRANS_SMALL_DOWNLOAD = 0x27,  // 小文件下载

    // 响应类型: RESPONSE (0x30-0x39)
    SUCCESS_REGIS = 0x30,     // 注册成功
    SUCCESS_LOGIN = 0x31,     // 登录成功
    INVALID_DIR = 0x32,       // cd失败，目录不合法
    CMD_SUCCESS = 0x33,       // 命令成功
    MKDIR_FAILED = 0x34,      // 创建目录失败
    REMOVE_DIR_FAILED = 0x36, // 删除目录失败
    RETRANS = 0x38,           // 重新传输
    TRANS_SUCCESS = 0x39,     // 传输成功

    // 错误类型: ERROR (0x40-0x45)
    ERR_NAME_CONFLICT = 0x40,   // 重名错误
    ERR_PASSWORD_INVALID = 0x41,// 密码错误
    ERR_USER_NOT_FOUND = 0x42,  // 未找到用户名
    ERR_TRANS_ARGS = 0x43,      // 传输参数错误
    ERR_FILE = 0x44,            // 文件操作错误
    ERR_NET = 0x45              // 网络错误
} tlvType;

tlv_t* tlv_create(uint8_t type, const void* data, uint16_t len);

// TLV释放函数
// 参数: tlv - 要释放的TLV指针
void tlv_free(tlv_t* tlv);

// 发送TLV包
int tlv_send(int sockfd, tlv_t* tlv);


// 接收TLV包
tlv_t* tlv_recv(int sockfd);



// 5. handle
void handle_trans(tlv_t* p);

int handle_command(Session_t* session, tlv_t* tlv);



// 6. usr

int salt_maker(char *salt);
int usr_register(server_context_t * ctx,tlv_t *tlv, int net_fd, MYSQL* conn);
int usr_login(server_context_t * ctx,tlv_t* tlv, int net_fd, MYSQL* conn);


// 7. cmd 

// 路径规范化，将cwd和用户输入的路径input拼接成为规范化的虚拟路径，将结果存到output
int normalize_virtual_path(const char* cwd, const char* input, char* output, size_t outlen);

// 目录操作命令
// 1.cd命令
int cmd_cd(Session_t* session,const char* path);

// 2.ls命令
int cmd_ls(Session_t* session);

// 3.mkdir命令
int cmd_mkdir(Session_t* session, const char* path);

// 4.remove命令
int cmd_remove(Session_t* session, const char* path);

// 5.upload命令，文件上传接口
int cmd_upload(Session_t* session, const char* path);

// 6.download命令，文件下载接口
int cmd_download(Session_t* session, const char* path);

// 8. trans暂搁置






//9. auth

//9.1 salt
int salt_maker(char *salt);


//9.2 token
#define SERVER_SECRET_KEY "iS#9qP@W7Kz!$n3eH&tYfGpX8RcL0vQ2"
int token_maker(const char* key, const char* usr_name, char* token, size_t token_buf_len) ;
int token_validate(const char* key, const char* usr_name, const char* token, char* out_sub, size_t out_sub_len);



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
    server_context_t ctx;
    server_init(&ctx, "./server.config", "./log");

    time_t last_tick = time(NULL); // 初始化时间轮的 last_tick

    while (1) {
        //==== 时间轮 tick：每秒 tick 一次，批量处理超时 ===
        time_t now = time(NULL);
        if (now != last_tick) {
            last_tick = now;
            timeout_wheel_tick(&ctx.timeout_wheel, close_fd_on_timeout); 
        }

        struct epoll_event ready_arr[WORKER_NUM + 4]; // 定义 epoll 事件数组
        int ready_num = epoll_wait(ctx.epfd, ready_arr, WORKER_NUM + 4, 100);
        if (ready_num == 0) {
            // 时间轮 tick 统一处理超时，无就绪也无所谓
            continue;
        }


        

        for (int i = 0; i < ready_num; ++i) {
            int fd = ready_arr[i].data.fd;
            // 新连接
            if (fd == ctx.listen_fd) {
            int netfd = accept(ctx.listen_fd, NULL, NULL);
            ERROR_CHECK(netfd, -1, "accept");

            // 新连接加入监听和时间轮，开始计时
            epoll_add(ctx.epfd, netfd);
            timeout_wheel_touch(&ctx.timeout_wheel, netfd);
            }
            // 退出信号处理
            else if (fd == ctx.exitPipe[0]) {
                // 退出唤醒所有线程优雅退出
                ctx.threadPool.exitFlag = 1;
                pthread_cond_broadcast(&ctx.threadPool.taskQueue.cond);
                for (int j = 0; j < ctx.threadPool.threadNum; ++j) {
                    pthread_join(ctx.threadPool.threads[j], NULL);
                }
                pthread_exit(NULL);
            }
            // 收到 TLV 包处理
            else {
                tlv_t* tlv = tlv_recv(fd);
                if (!tlv) {
                    // 关闭连接并清理资源
                    epoll_del(ctx.epfd, fd);
                    close(fd);
                    continue;
                }

                // 每收到一次客户端请求包，都刷新 fd 的超时时间
                timeout_wheel_touch(&ctx.timeout_wheel, fd);

                // ===== 处理 TOKEN 包 =====需要合并入/2里
                if (tlv->type == TRANS_TOKEN) {
                    // char usr_name[64], token[128], out_sub[256];
                    // size_t out_sub_len = sizeof(out_sub);

                    // // 从 TLV 中解析用户名和 Token
                    // parse_token_tlv(tlv, usr_name, sizeof(usr_name), token, sizeof(token));

                    // // 校验 Token
                    // if (token_validate("secret_key", usr_name, token, out_sub, out_sub_len) != 0) {
                    //     fprintf(stderr, "Token 验证失败: fd=%d\n", fd);
                    //     tlv_free(tlv);
                    //     continue;
                    // }

                    // // Token 验证通过，解析分片信息并入队
                    // chunk_info_t chunk_info;
                    // parse_chunk_info_tlv(tlv, &chunk_info);

                    // task_param_t task_param;
                    // memset(&task_param, 0, sizeof(task_param));
                    // task_param.download_large.netfd = fd;
                    // strncpy(task_param.download_large.filename, chunk_info.filename, sizeof(task_param.download_large.filename));
                    // task_param.download_large.offset = chunk_info.offset;
                    // task_param.download_large.size = chunk_info.size;
                    // task_param.download_large.chunk_index = chunk_info.chunk_index;
                    // task_param.download_large.chunk_count = chunk_info.chunk_count;

                    // // 将分片任务入队
                    // enQueue(&ctx.threadPool.taskQueue, TASK_DOWNLOAD_LARGE, &task_param);

                    // tlv_free(tlv);
                    // continue;
                }

                // ===== 上传/下载任务分发 =====
                if (tlv->type / 16 == 2) { // 上传/下载
                    // task_param_t task_param;
                    // memset(&task_param, 0, sizeof(task_param_t));
                    // task_param.upload.netfd = fd;

                    // if (tlv->type == CMD_UPLOAD) {
                    //     // 上传任务入队
                    //     enQueue(&ctx.threadPool.taskQueue, TASK_UPLOAD, &task_param);
                    // }
                    // else if (tlv->type == CMD_DOWNLOAD) {
                    //     // 获取文件大小
                    //     size_t file_size = get_file_size(tlv->value);

                    //     //小文件返回允许下载，大文件返回信息让客户端创子线程带token来
                        
                    //     if (file_size <= 100 * 1024 * 1024) { // 小文件下载
                    //         enQueue(&ctx.threadPool.taskQueue, TASK_DOWNLOAD_SMALL, &task_param);
                    //     }
                    //     else { // 大文件按分片下载
                    //         size_t offset = 0;
                    //         unsigned int chunk_index = 0;
                    //         unsigned int chunk_count = (file_size + 100 * 1024 * 1024 - 1) / (100 * 1024 * 1024);

                    //         while (offset < file_size) {
                    //             size_t chunk_size = (file_size - offset > 100 * 1024 * 1024) ? 100 * 1024 * 1024 : file_size - offset;

                    //             task_param_t chunk_param;
                    //             memset(&chunk_param, 0, sizeof(chunk_param));
                    //             chunk_param.download_large.netfd = fd;
                    //             strncpy(chunk_param.download_large.filename, tlv->value, sizeof(chunk_param.download_large.filename));
                    //             chunk_param.download_large.offset = offset;
                    //             chunk_param.download_large.size = chunk_size;
                    //             chunk_param.download_large.chunk_index = chunk_index;
                    //             chunk_param.download_large.chunk_count = chunk_count;

                    //             // 分片任务入队
                    //             enQueue(&ctx.threadPool.taskQueue, TASK_DOWNLOAD_LARGE, &chunk_param);
                    //             offset += chunk_size;
                    //             chunk_index++;
                    //         }
                    //     }
                    // }
                    // tlv_free(tlv);
                }
                else {
                    // 其他命令
                    handle_command(&ctx.session[fd], tlv);
                    tlv_free(tlv);
                }
            }
        }
    }
    return 0;
}



// 0.线程池



// 初始化任务队列



void taskQueueDestroy(taskQueue_t* queue) {
    pthread_mutex_lock(&queue->mutex);

    // 清空队列中的所有任务节点，释放内存
    while (queue->pFront != NULL) {
        node_t* node = queue->pFront;
        queue->pFront = queue->pFront->pNext;
        free(node);
    }

    queue->pRear = NULL;
    queue->queueSize = 0;

    pthread_mutex_unlock(&queue->mutex);

    // 销毁互斥锁和条件变量
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
}

// 初始化任务队列
int taskQueueInit(taskQueue_t* queue) {
    queue->pFront = queue->pRear = NULL; // 队列为空
    queue->queueSize = 0;               // 队列大小初始化为 0
    pthread_mutex_init(&queue->mutex, NULL); // 初始化互斥锁
    pthread_cond_init(&queue->cond, NULL); 
    return 0;// 初始化条件变量
}


// 入队任务
void enQueue(taskQueue_t* queue, task_type_t type, task_param_t* param) {
    // 创建新任务节点
    node_t* newNode = (node_t*)malloc(sizeof(node_t));
    if (!newNode) {
        perror("Failed to allocate memory for new task node");
        return;
    }
    newNode->type = type;
    memcpy(&newNode->param, param, sizeof(task_param_t));
    newNode->pNext = NULL;

    pthread_mutex_lock(&queue->mutex);

    // 添加任务到队列尾部
    if (queue->pRear == NULL) {
        queue->pFront = queue->pRear = newNode; // 队列为空时，头尾指针都指向新节点
    }
    else {
        queue->pRear->pNext = newNode; // 队列不为空时，链到尾部
        queue->pRear = newNode;
    }
    queue->queueSize++;

    // 通知等待的线程有新任务
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

// 出队任务
node_t* deQueue(taskQueue_t* queue) {
    pthread_mutex_lock(&queue->mutex);

    // 等待任务队列非空
    while (queue->queueSize == 0) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    // 取出队列头部任务
    node_t* frontNode = queue->pFront;
    queue->pFront = queue->pFront->pNext;

    if (queue->pFront == NULL) {
        queue->pRear = NULL; // 队列为空时，尾指针也置为 NULL
    }
    queue->queueSize--;

    pthread_mutex_unlock(&queue->mutex);
    return frontNode;
}

// 销毁线程池，包括任务队列（防止资源泄露）
void threadPoolDestroy(thread_pool_t* pool) {
    // 通知所有线程退出
    pthread_mutex_lock(&pool->taskQueue.mutex);
    pool->exitFlag = 1;
    pthread_cond_broadcast(&pool->taskQueue.cond);
    pthread_mutex_unlock(&pool->taskQueue.mutex);

    // 等待所有线程退出
    for (int i = 0; i < pool->threadNum; ++i) {
        pthread_join(pool->threads[i], NULL);
    }

    // 释放线程数组
    free(pool->threads);

    // 销毁任务队列
    taskQueueDestroy(&pool->taskQueue);
}

// 线程池初始化函数
int threadPoolInit(thread_pool_t* pool, int threadNum) {
    if (threadNum <= 0) {
        fprintf(stderr, "无效的线程数量: %d\n", threadNum);
        return -1; 
    }

    pool->threadNum = threadNum;
    pool->exitFlag = 0; // 初始化退出标志

    // 分配线程数组内存
    pool->threads = (pthread_t*)malloc(threadNum * sizeof(pthread_t));
    if (!pool->threads) {
        perror("分配线程内存失败");
        return -1;
    }

    // 初始化任务队列
    if (taskQueueInit(&pool->taskQueue) != 0) {
        fprintf(stderr, "任务队列初始化失败\n");
        free(pool->threads);
        return -1;
    }

    // 创建线程
    for (int i = 0; i < threadNum; ++i) {
        if (pthread_create(&pool->threads[i], NULL, workerThread, pool) != 0) {
            perror("创建线程失败"); 
            pool->threadNum = i; // 已成功创建的线程数

            // 取消已创建的线程
            for (int j = 0; j < i; ++j) {
                pthread_cancel(pool->threads[j]);
            }

            // 释放资源
            free(pool->threads);
            taskQueueDestroy(&pool->taskQueue);
            return -1;
        }
    }

    return 0; 
}


// 任务处理函数
void* workerThread(void* arg) {
    thread_pool_t* pool = (thread_pool_t*)arg;

    while (1) {
        if (pool->exitFlag) break;

        // 从任务队列中取出任务
        node_t* task = deQueue(&pool->taskQueue);
        if (task) {
            switch (task->type) {
                case TASK_UPLOAD:
                    // 处理上传任务
                    printf("处理上传任务: %s\n", task->param.upload.filename);
                    break;

                case TASK_DOWNLOAD_SMALL:
                    // 处理小文件下载任务
                    printf("处理单线程下载任务: %s\n", task->param.download_small.filename);
                    break;

                case TASK_DOWNLOAD_LARGE:
                    // 处理分块下载任务
                    printf("处理分块下载任务: %u/%u of file: %s\n",
                           task->param.download_large.chunk_index + 1,
                           task->param.download_large.chunk_count,
                           task->param.download_large.filename);
                    break;

                default:
                    // 未知任务类型
                    printf("未知任务类型\n");
            }

            // 释放任务资源
            free(task);
        }
    }
    return NULL;
}



// 信号处理函数
void handler(int sig) {
    printf("收到信号 %d , 退出中...\n", sig);
}


// 1. server_init函数

int server_init(server_context_t* ctx, const char* conf_path, const char* log_path) {
    // 1. 日志系统优先
    init_logger(log_path);

    // 2. 退出管道、信号
    if (pipe(ctx->exitPipe) == -1) {
        perror("Failed to create pipe");
        close_logger();
        return -1;
    }

    if (fork() != 0) {
        // 父进程逻辑
        close(ctx->exitPipe[0]);
        signal(SIGUSR1, sig_handler1);
        signal(SIGINT, sig_handler1);
        wait(NULL); // 等待子进程退出
        close(ctx->exitPipe[1]);
        close_logger(); // 关闭日志系统
        exit(0);
    }

    // 子进程逻辑
    signal(SIGINT, sig_handler2);
    close(ctx->exitPipe[1]);

    // 3. 线程池初始化（只用于上传/下载这样的长命令）
    if (threadPoolInit(&ctx->threadPool, WORKER_NUM) != 0) {
        fprintf(stderr, "Failed to initialize thread pool\n");
        close_logger();
        return -1;
    }

    // 4. TCP初始化
    ctx->listen_fd = tcpInit(conf_path);
    if (ctx->listen_fd == -1) {
        fprintf(stderr, "Failed to initialize TCP\n");
        close_logger();
        return -1;
    }

    ctx->epfd = epoll_create(1);
    if (ctx->epfd == -1) {
        perror("Failed to create epoll");
        close_logger();
        return -1;
    }

    // 5. 任务队列初始化
    taskQueueInit(&ctx->threadPool.taskQueue);

    // 6. 时间轮初始化
    timeout_wheel_init(&ctx->timeout_wheel);

    // 7. epoll添加监听
    epoll_add(ctx->epfd, ctx->listen_fd);
    epoll_add(ctx->epfd, ctx->exitPipe[0]);

    // 8. 数据库连接
    ctx->conn = NULL;
    if (db_connect(&ctx->conn) != 0) {
        fprintf(stderr, "Failed to connect to database\n");
        close_logger();
        return -1;
    }

    // 9. session清零
    memset(ctx->session, 0, sizeof(ctx->session));
    ctx->session_cnt = 0;
    memset(ctx->hashmap,0,sizeof(ctx->session));

    return 0; // 子进程返回，父进程不返回
}

//1.0 session
// session结构体数据初始化
int session_insert(server_context_t* ctx,MYSQL* conn,const char* user_name,int netfd){
	ctx->session[ctx->session_cnt].netfd = netfd;
	memcpy(ctx->session[ctx->session_cnt].user_name,user_name,strlen(user_name)+1);
	memcpy(ctx->session[ctx->session_cnt].virtual_cwd,"/",2);
	ctx->session[ctx->session_cnt].cwd_id = vf_get_id_by_path_user(conn, ctx->session->virtual_cwd, user_name);
	ctx->session[ctx->session_cnt].conn = conn;
	++ctx->session_cnt;
	return 0;
}

//clean调用release完成session结构体的释放
int session_clean(server_context_t* ctx,int netfd){ 
    // 获取当前要删除的session在数组中的下标
	int index = ctx->hashmap[netfd];
	int last = ctx->session_cnt - 1;
	
	// 释放被覆盖（即将被删除的）session资源
	session_release(&ctx->session[index]);
	if(index != last){
		// 覆盖删除：用最后一个session覆盖当前session
        ctx->session[index] = ctx->session[last];
		
		// 更新hashmap，让最后一个session的netfd映射到新位置
        ctx->hashmap[ctx->session[index].netfd] = index;
		
		// 覆盖hashmap原最后一个元素为无效值
        ctx->hashmap[ctx->session[last].netfd] = -1;
	}
	
	// 释放最后一个session的资源（如index==last时，避免资源泄漏）
    session_release(&ctx->session[last]);
	
	// 标记已删除
    ctx->hashmap[netfd] = -1;
	
	ctx->session_cnt --;
	
	return 0;
}
void session_release(Session_t* session){
	// 关闭MYSQL连接并重置指针
    if (session->conn) {
        mysql_close(session->conn);
        session->conn = NULL;
    }
	
	// 重置netfd
    session->netfd = -1;
	
	// 清空用户名
    memset(session->user_name, 0, sizeof(session->user_name));
	
	// 清空虚拟目录
    memset(session->virtual_cwd, 0, sizeof(session->virtual_cwd));
	
	// 重置cwd_id
    session->cwd_id = -1;
}




int epoll_add(int epfd, int fd){
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = fd;
    epoll_ctl(epfd,EPOLL_CTL_ADD,fd,&event);
    return 0;
}
int epoll_del(int epfd, int fd){
    epoll_ctl(epfd,EPOLL_CTL_DEL,fd,NULL);
    return 0;
}




// 1.2 tcpInit

int tcpInit(const char* filename) {
    /*
       server.conf格式
       ip:172.28.138.3
       port:23456
       host:localhost
   */
    FILE* fp = fopen(filename, "r");
    ERROR_CHECK(fp, NULL, "fopen failed");

    char ip[16] = { 0 };
    char port[6] = { 0 };  // 端口最大65535（5位）+1
    char buf[1024] = { 0 };

    // 解析IP行
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        fprintf(stderr, "Failed to read IP line\n");
        return -1;
    }
    char* p = strchr(buf, ':');
    if (p && p[1]) {
        // 移除可能的换行符
        char* nl = strchr(p + 1, '\n');
        if (nl) *nl = '\0';
        strncpy(ip, p + 1, sizeof(ip) - 1);
    }

    // 解析Port行
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

        // 修复：允许最大5位端口
        if (len > 0 && len <= sizeof(port) - 1) {
            memcpy(port, beg, len); // 比strncpy更高效
            port[len] = '\0';
        }
        else {
            fclose(fp);
            fprintf(stderr, "Invalid port format\n");
            return -1;
        }
    }

    // 解析Host行（虽未使用，但保留）
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        fprintf(stderr, "Failed to read Host line\n");
        return -1;
    }

    fclose(fp);

    // 创建套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == 0){
        log_error(__FILE__, __LINE__, "Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int flag = 1;
    if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&flag,sizeof(flag))){
        log_error(__FILE__, __LINE__, "Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // 配置地址
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);

    // 绑定并监听
    int ret = bind(sockfd,(struct sockaddr *)&addr,sizeof(addr));
    if(ret == -1){
        log_error(__FILE__, __LINE__, "Bind failed");
        exit(EXIT_FAILURE);
    }
    if(listen(sockfd,50)<0){
        log_error(__FILE__, __LINE__, "Listen failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

//1.3 超时队列
/**

 * 初始化超时轮结构体
 */
void timeout_wheel_init(timeout_wheel_t* wheel) {
    wheel->timer = 0;
    memset(wheel->index, 0, sizeof(wheel->index));
    for (int i = 0; i < TIME_SLICE; ++i) {
        wheel->slots[i].head = NULL;
        wheel->slots[i].tail = NULL;
        wheel->slots[i].size = 0;
    }
}

/**
 * 从slot链表中删除指定netfd
 */

void _remove_usr_from_slot(slot_list_t* slot, int netfd) {
    slot_node_t* cur = slot->head, * prev = NULL;
    while (cur) {
        if (cur->netfd == netfd) {
            if (prev) prev->next = cur->next;
            else slot->head = cur->next;
            if (cur == slot->tail) slot->tail = prev;
            free(cur);
            slot->size--;
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

/**
 * 新请求到达时调用，新旧对象被刷新，重新插入slot。
 * netfd必须在0~MAX_FD-1范围内
 */

void timeout_wheel_touch(timeout_wheel_t* wheel, int netfd) {
    // 如果已存在于某slot，先删除
    int old_index = wheel->index[netfd];
    if (old_index > 0 || (old_index == 0 && wheel->slots[0].size > 0)) {
        _remove_usr_from_slot(&wheel->slots[old_index], netfd);
    }
    // 计算应该插入的新slot
    int slot_index = (wheel->timer + TIME_SLICE - 1) % TIME_SLICE;
    slot_node_t* node = (slot_node_t*)calloc(1, sizeof(slot_node_t));
    node->netfd = netfd;
    node->next = NULL;

    // 插入slot尾部
    slot_list_t* slot = &wheel->slots[slot_index];
    if (slot->tail) {
        slot->tail->next = node;
        slot->tail = node;
    }
    else {
        slot->head = slot->tail = node;
    }
    slot->size++;
    wheel->index[netfd] = slot_index;
}

/**
 *  定时器每秒调用，推进timer指针，批量超时当前slot全部对象
 *  超时对象通过回调处理
 */
void timeout_wheel_tick(timeout_wheel_t* wheel, void (*on_timeout)(int netfd)) {
    slot_list_t* slot = &wheel->slots[wheel->timer];
    slot_node_t* cur = slot->head;
    while (cur) {
        // 超时处理回调
        on_timeout(cur->netfd);
        wheel->index[cur->netfd] = 0;
        slot_node_t* tmp = cur;
        cur = cur->next;
        free(tmp);
    }
    slot->head = slot->tail = NULL;
    slot->size = 0;
    // timer前进
    wheel->timer = (wheel->timer + 1) % TIME_SLICE;
}

void close_fd_on_timeout(int fd) {
    // 关闭超时fd，移除epoll监听，做清理
    //epoll_del(epfd, fd);
    close(fd);
    // 其它资源释放（如session、内存等）

}




// 2. database 函数



// 数据库连接函数
int db_connect(MYSQL** pconn){
    *pconn = mysql_init(NULL);

    const char* host = "localhost";
    const char* usr = "root";
    const char* passwd = "1234";
    const char* db = "NetDisk";

    MYSQL* conn = mysql_real_connect(*pconn,host,usr, passwd, db, 0, NULL, 0);
    PSQL_ERROR_CHECK(conn,NULL,*pconn,"mysql_real_connect");

    return 0;
}

// 往vf表中插入一条记录
int vf_insert(MYSQL* conn,const VirtualFileInfo_t *info) {
    char query[4096];
    snprintf(query, sizeof(query),
             "INSERT INTO virtual_file (file_name, user_name, parent_id, sha256, file_type, path, link) "
             "VALUES ('%s', '%s', %d, '%s', '%s', '%s', %d)",
             info->file_name, info->user_name, info->parent_id, info->sha256,
             info->file_type, info->path, info->link);
    int ret = mysql_query(conn, query);
    SQL_ERROR_CHECK(ret, 0, conn, "insert virtual_file");
    return 0;
}

// 根据虚拟路径和用户名获取文件id
int vf_get_id_by_path_user(MYSQL* conn,const char *path, const char *user_name){
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id FROM virtual_file WHERE path='%s' AND user_name='%s'", path, user_name);
    int ret = mysql_query(conn, query);
    SQL_ERROR_CHECK(ret, 0, conn, "select id by path");
    MYSQL_RES *result = mysql_store_result(conn);
    if (!result) return -1;
    MYSQL_ROW row = mysql_fetch_row(result);
    int id = -1;
    if (row) id = atoi(row[0]);
    mysql_free_result(result);
    return id;
}

// 获取parent_id下所有文件/目录
VirtualFileInfo_t* vf_list_by_parent_id(MYSQL* conn,int parent_id, const char *user_name, int *count) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id, file_name, user_name, parent_id, sha256, file_type, path, link FROM virtual_file "
             "WHERE parent_id=%d AND user_name='%s' order by file_name", parent_id, user_name);
    int ret = mysql_query(conn, query);
    // SQL_ERROR_CHECK(ret, 0, conn, "list by parent");
    if(ret !=0 ){
        fprintf(stderr,"Error:%s\n",mysql_error(conn));
        return NULL;
    }
    MYSQL_RES *result = mysql_store_result(conn);
    if (!result) { *count = 0; return NULL; }
    int rows = mysql_num_rows(result);
    *count = rows;
    if (rows == 0) { mysql_free_result(result); return NULL; }
    VirtualFileInfo_t *infos = (VirtualFileInfo_t*)malloc(rows * sizeof(VirtualFileInfo_t));
    MYSQL_ROW row;
    int idx = 0;
    while ((row = mysql_fetch_row(result))) {
        infos[idx].id = atoi(row[0]);
        strncpy(infos[idx].file_name, row[1], sizeof(infos[idx].file_name) - 1);
        strncpy(infos[idx].user_name, row[2], sizeof(infos[idx].user_name) - 1);
        infos[idx].parent_id = atoi(row[3]);
        strncpy(infos[idx].sha256, row[4], sizeof(infos[idx].sha256) - 1);
        strncpy(infos[idx].file_type, row[5], sizeof(infos[idx].file_type) - 1);
        strncpy(infos[idx].path, row[6], sizeof(infos[idx].path) - 1);
        infos[idx].link = atoi(row[7]);
        idx++;
    }
    mysql_free_result(result);
    return infos;
}

// 根据id查信息
int vf_get_info_by_id(MYSQL *conn, int id, VirtualFileInfo_t *info) {
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT id, file_name, user_name, parent_id, sha256, file_type, path, link FROM virtual_file WHERE id=%d", id);
    int ret = mysql_query(conn, query);
    SQL_ERROR_CHECK(ret, 0, conn, "get info by id");
    MYSQL_RES *result = mysql_store_result(conn);
    if (!result) return -1;
    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) { mysql_free_result(result); return -1; }
    info->id = atoi(row[0]);
    strncpy(info->file_name, row[1], sizeof(info->file_name) - 1);
    strncpy(info->user_name, row[2], sizeof(info->user_name) - 1);
    info->parent_id = atoi(row[3]);
    strncpy(info->sha256, row[4], sizeof(info->sha256) - 1);
    strncpy(info->file_type, row[5], sizeof(info->file_type) - 1);
    strncpy(info->path, row[6], sizeof(info->path) - 1);
    info->link = atoi(row[7]);
    mysql_free_result(result);
    return 0;
}

// 根据id删除记录
int vf_delete_by_id(MYSQL *conn, int id) {
    // 先查是否目录，若是目录递归删除其所有子节点
    VirtualFileInfo_t info;
    if (vf_get_info_by_id(conn, id, &info) != 0) return -1;
    if (strcmp(info.file_type, "dir") == 0) {
        // 递归删除所有子节点
        int child_count = 0;
        VirtualFileInfo_t* children = vf_list_by_parent_id(conn, id, info.user_name, &child_count);
        for (int i = 0; i < child_count; ++i) {
            vf_delete_by_id(conn, children[i].id);
        }
        if (children) free(children);
    }
    // 删除自身
    char query[128];
    snprintf(query, sizeof(query), "DELETE FROM virtual_file WHERE id=%d", id);
    int ret = mysql_query(conn, query);
    SQL_ERROR_CHECK(ret, 0, conn, "delete by id");
    return 0;
}

// 判断文件或目录在当前目录下是否存在
int vf_exist_in_dir(MYSQL *conn, int parent_id, const char *file_name, const char *user_name, const char *file_type) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id FROM virtual_file WHERE parent_id=%d AND file_name='%s' AND user_name='%s' AND file_type='%s'",
             parent_id, file_name, user_name, file_type);
    int ret = mysql_query(conn, query);
    SQL_ERROR_CHECK(ret, 0, conn, "exist in dir");
    MYSQL_RES *result = mysql_store_result(conn);
    int exist = mysql_num_rows(result) > 0;
    mysql_free_result(result);
    return exist;
}

// 用户注册时文件表默认插入函数
int vf_default_insert(MYSQL* conn,const char* user_name){
    char query[1024];
    int ret;
    unsigned int root_id;

    // 1.插入根目录
    snprintf(query,sizeof(query),
        "INSERT INTO virtual_file (file_name,user_name,parent_id,file_type,path,link)"
        " VALUES ('/','%s',-1,'d','/',-1)",user_name);
    ret = mysql_query(conn,query);
    if(ret != 0) {
        // printf("Insert root dir error: %s\nSQL: %s\n", mysql_error(conn), query);
        return 1;
    }
    root_id = mysql_insert_id(conn);

    // 2.插入默认文件夹
    const char* dirs[] = {"photo","project","music"};
    for(int i=0;i<3;i++){
        snprintf(query,sizeof(query),
            "INSERT INTO virtual_file(file_name,user_name,parent_id,file_type,path,link)"
            " VALUES ('%s','%s',%u,'d','/%s',-1)",
            dirs[i],user_name,root_id,dirs[i]);
        ret = mysql_query(conn,query);
        if(ret != 0) {
            // printf("Insert dir '%s' error: %s\nSQL: %s\n", dirs[i], mysql_error(conn), query);
            return 2;
        }
    }

    // 3.插入默认文件
    struct{
        const char* name;
        const char* path;
    }files[] = {
        {"给泥鳅的一封信.txt","/给泥鳅的一封信.txt"},
        {"使用说明.txt","/使用说明.txt"},
        {"最终用户许可协议.txt","/最终用户许可协议.txt"}
    };
    for(int i=0;i<3;i++){
        snprintf(query,sizeof(query),
            "INSERT INTO virtual_file(file_name,user_name,parent_id,file_type,path,link)"
            " VALUES ('%s','%s',%u,'f','%s',-1)",
            files[i].name,user_name,root_id,files[i].path);
        ret = mysql_query(conn,query);
        if(ret != 0) {
            // printf("Insert file '%s' error: %s\nSQL: %s\n", files[i].name, mysql_error(conn), query);
            return 3;
        }
    }
    return 0;
}

// 用户名查重，返回1表示重名，0表示不重名
int ui_exist_user_name(MYSQL* conn,const char* user_name){
	char query[256];
	snprintf(query,sizeof(query),
		"SELECT id FROM user_info WHERE user_name = '%s'",user_name);
	int ret = mysql_query(conn,query);
	SQL_ERROR_CHECK(ret,0,conn,"mysql_query");
	MYSQL_RES* result = mysql_store_result(conn);
	int exist = mysql_num_rows(result)>0;
	mysql_free_result(result);
	return exist;
}

// 用户表插入
int ui_insert(MYSQL* conn, const char* user_name, const char* salt, const char* encrypt_pwd) {
    char query[512];
    snprintf(query, sizeof(query),
             "INSERT INTO user_info (user_name, salt, encrypt_pwd) VALUES ('%s', '%s', '%s')",
             user_name, salt, encrypt_pwd);

    int ret = mysql_query(conn, query);
    if (ret != 0) {
        fprintf(stderr, "mysql_query failed: %s\n", mysql_error(conn));
        return 1; // 插入失败
    }
    return 0; // 插入成功
}

// 根据用户名查salt值和密文密码
int ui_get_salt_encrypt(MYSQL* conn,const char* user_name,char salt[],int salt_size,char crptpswd[],int crptpswd_size){
	char query[512];
	snprintf(query, sizeof(query),
        "SELECT salt, encrypt_pwd FROM user_info WHERE user_name='%s'", user_name);

    int ret = mysql_query(conn, query);
    if (ret != 0) {
        // fprintf(stderr, "mysql_query failed: %s\n", mysql_error(conn));
        return 1; // 查询失败
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) {
        // fprintf(stderr, "mysql_store_result failed: %s\n", mysql_error(conn));
        return 2; // 获取结果集失败
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        mysql_free_result(result);
        return 3; // 用户不存在
    }

    strncpy(salt, row[0], salt_size - 1);
    salt[salt_size - 1] = '\0';
    strncpy(crptpswd, row[1], crptpswd_size - 1);
    crptpswd[crptpswd_size - 1] = '\0';

    mysql_free_result(result);
    return 0; // 成功
}


// 3. logger函数

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

void log_upload(const char* username, const char* filename, long size) {
    if (log_file == NULL) return;

    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[UPLOAD][%s] User: %s, File: %s, Size: %ld bytes\n",
            time_str, username, filename, size);
    fflush(log_file);
}

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

void log_error(const char* file, int line, const char* message, ...) {
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



// 4. tlv函数


tlv_t* tlv_create(uint8_t type, const void* data, uint16_t len) {
    // 检查参数有效性
    if ( len > 0 && data == NULL ) {
        fprintf(stderr, "错误: 非空长度需要有效数据指针\n");
        return NULL;
    }

    // 计算总内存大小（结构体 + 数据区）
    size_t total_size = sizeof(tlv_t) + len;
    tlv_t* tlv = (tlv_t*)malloc(total_size);
    if ( tlv == NULL ) {
        perror("内存分配失败");
        return NULL;
    }

    // 填充TLV头部
    tlv->type = type;
    tlv->len = len;

    // 如果有数据则拷贝
    if ( len > 0 && data != NULL ) {
        memcpy(tlv->value, data, len);
    }

    return tlv;
}

void tlv_free(tlv_t* tlv) {
    if ( tlv ) {
        free(tlv);
    }
}

int tlv_send(int sockfd, tlv_t* tlv) {
    // 发送头部 (type + len)
    uint8_t header[3];
    header[0] = tlv->type;
    *(uint16_t*)(header + 1) = htons(tlv->len); // 网络字节序

    if ( send(sockfd, header, 3, 0) != 3 ) {
        return -1; // 发送头部失败
    }

    // 发送数据体 (如果有)
    if ( tlv->len > 0 && send(sockfd, tlv->value, tlv->len, 0) != tlv->len ) {
        return -1; // 发送数据失败
    }
    return 0;
}

tlv_t* tlv_recv(int sockfd) {
    // 接收头部
    uint8_t header[3];
    if ( recv(sockfd, header, 3, MSG_WAITALL) != 3 ) {
        return NULL; // 接收头部失败
    }

    // 解析头部
    uint8_t type = header[0];
    uint16_t len = ntohs(*(uint16_t*)(header + 1)); // 主机字节序

    // 创建TLV包
    tlv_t* tlv = (tlv_t*)malloc(sizeof(tlv_t) + len);
    if ( !tlv ) return NULL;

    tlv->type = type;
    tlv->len = len;

    // 接收数据体 (如果有)
    if ( len > 0 && recv(sockfd, tlv->value, len, MSG_WAITALL) != len ) {
        free(tlv);
        return NULL;
    }
    return tlv;
}





// 5. handle函数




int handle_command(Session_t* session, tlv_t* tlv){
    uint8_t type = tlv->type;
    char path[1024]={0};
    if(tlv->len > 0){
        memcpy(path,tlv->value,tlv->len);
    }
    switch(type){
    case CMD_SHORT_CD:
        cmd_cd(session,NULL);
        break;
    case CMD_LONG_CD:
        cmd_cd(session,path);
        break;
    case CMD_SHORT_LS:
        cmd_ls(session);
        break;
    case CMD_MKDIR:
        cmd_mkdir(session,path);
        break;
    case CMD_REMOVE:
        cmd_remove(session,path);
        break;
    case CMD_UPLOAD:
        cmd_upload(session,path);
        break;
    case CMD_DOWNLOAD:
        cmd_download(session,path);
        break;
    default:
        break;
    }
    return 0;
}





// 6. usr函数

//int user_id?传入结构体中空闲的结构体id
int usr_register(server_context_t* ctx,tlv_t *tlv, int net_fd, MYSQL* conn)
{
    char usr_name[512] = {0};
    char crptpswd[512] = {0};
    char salt[SALT_LEN];
    char token[512]= { 0 };

    //查数据库验证重名
    memcpy(usr_name, tlv->value, tlv->len);
    if (ui_exist_user_name(conn,usr_name))
    {
            //发送重名空包
            tlv_t* t = tlv_create(ERR_NAME_CONFLICT, NULL, 0);
            tlv_send(net_fd, t);
            tlv_free(t);
            return 1;
    }
    else {
        //不重名发送盐值
        salt_maker(salt);
        tlv_t* t = tlv_create(AUTH_SALT,salt , strlen(salt)+1);
        tlv_send(net_fd, t);
        tlv_free(t);
    }

    //接收第二个包
    tlv_t*  t = tlv_recv(net_fd);

    /*
    不正确的包直接退出
    用户名、salt和密文密码一起插入用户表usr_name、crptpswd、salt
    */
    if (AUTH_REGISTER != t->type || t->len == 0)return 1;
    memcpy(crptpswd, t->value, t->len);
    tlv_free(t);
    t=NULL;
    //插入数据库
    vf_default_insert(conn, usr_name);

    //注册成功，返回token
    token_maker(SERVER_SECRET_KEY, usr_name, token, sizeof(token));
    t = tlv_create(AUTH_TOKEN, token, strlen(token) + 1);
    tlv_send(net_fd, t);
    tlv_free(t);


    //更新session
    session_insert(ctx,conn,usr_name,net_fd);
    //注册信息写入log
    log_connection(net_fd);

}

int usr_login(server_context_t* ctx,tlv_t* tlv, int net_fd, MYSQL* conn)
{

    char usr_name[512] = { 0 };
    char crptpswd[512] = { 0 };
    char salt[SALT_LEN];
    char token[512] = { 0 };



    // 查数据库验证用户存在
    memcpy(usr_name, tlv->value, tlv->len);
    if (ui_exist_user_name(conn, usr_name))
    {
        //用户存在，查sql获得盐值和密文密码保存，发送盐值
        ui_get_salt_encrypt(conn, usr_name, salt, SALT_LEN, crptpswd, sizeof(crptpswd));
        tlv_t* t = tlv_create(AUTH_SALT, salt, strlen(salt) + 1);
        tlv_send(net_fd, t);
        tlv_free(t);
    }
    else
    {
        //发送用户不存在空包
        tlv_t* t = tlv_create(ERR_USER_NOT_FOUND, NULL, 0);
        tlv_send(net_fd, t);
        tlv_free(t);
        return 1;
    }

    //收包验证密码：和crptpswd对比
    tlv_t* t = tlv_recv(net_fd);

    /*
    不正确的包返回错误并退出

    */

    if (AUTH_LOGIN != t->type || t->len == 0)
    {
        return 1;
    }
    char temp[512] = { 0 };
    memcpy(temp, t->value, t->len);
    tlv_free(t);
    t=NULL;
    //密码正确，返回token
    if (strcmp(temp, crptpswd) == 0)
    {

        token_maker(SERVER_SECRET_KEY, usr_name, token, sizeof(token));
        t = tlv_create(AUTH_TOKEN, token, strlen(token)+1);
        tlv_send(net_fd, t);
        tlv_free(t);
    }
    else//密码错误，返回错误空包
    {
        //发送用户不存在空包
        t = tlv_create(ERR_PASSWORD_INVALID, NULL, 0);
        tlv_send(net_fd, t);
        tlv_free(t);
        return 1;
    }

    //更新session
    session_insert(ctx,conn,usr_name,net_fd);
    //注册信息写入log
    log_connection(net_fd);

    return 0;
}


// 7. cmd 函数
// 路径规范化函数 
int normalize_virtual_path(const char* cwd, const char* input, char* output, size_t outlen) {
    if ( !cwd || !input || !output || outlen == 0 ) return -1;

    // 临时栈用于处理路径组件
    const char* components[256];
    int comp_count = 0;
    char temp[1024];

    // 1. 处理绝对路径或相对路径
    if ( input[0] == '/' ) {
        strncpy(temp, input, sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = 0;
    }
    else {
        snprintf(temp, sizeof(temp), "%s/%s", cwd, input);
    }

    // 2. 清理多余的“/”
    size_t len = strlen(temp);
    char cleaned[1024];
    int j = 0;
    int prev_slash = 0;
    for ( size_t i = 0; i < len && j < (int)sizeof(cleaned) - 1; ++i ) {
        if ( temp[i] == '/' ) {
            if ( !prev_slash ) cleaned[j++] = '/';
            prev_slash = 1;
        }
        else {
            cleaned[j++] = temp[i];
            prev_slash = 0;
        }
    }
    if ( j > 1 && cleaned[j - 1] == '/' ) j--;
    cleaned[j] = '\0';

    // 3. 拆分组件
    char* token;
    char* rest = cleaned;
    char* saveptr = NULL;
    while ( (token = strtok_r(rest, "/", &saveptr)) ) {
        rest = NULL;
        if ( strcmp(token, ".") == 0 ) {
            continue;
        }
        else if ( strcmp(token, "..") == 0 ) {
            if ( comp_count > 0 ) comp_count--;
            // 若已经到根，不再上溯
        }
        else {
            if ( comp_count < 256 )
                components[comp_count++] = token;
            else
                return -1; // 路径过深
        }
    }

    // 4. 拼接规范化路径
    if ( comp_count == 0 ) {
        if ( outlen < 2 ) return -1;
        strncpy(output, "/", outlen - 1);
        output[outlen - 1] = '\0';
        return 0;
    }
    output[0] = '\0';
    for ( int i = 0; i < comp_count; ++i ) {
        if ( strlen(output) + strlen(components[i]) + 2 > outlen ) return -1;
        strncat(output, "/", outlen - strlen(output) - 1);
        strncat(output, components[i], outlen - strlen(output) - 1);
    }
    return 0;
}

// cd命令
int cmd_cd(Session_t* session, const char* path) {
    char abs_path[256];
    //if(path == NULL || strlen(path) == 0){
    //    // 跳转回用户初始目录
    //    strncpy(session->virtual_cwd,session->root_path,sizeof(session->virtual_cwd)-1);
    //    session->virtual_cwd[sizeof(session->virtual_cwd)-1] = '\0';
    //    session->cwd_id = session->root_id;
    //    printf("切换到用户根目录: %s\n", session->virtual_cwd);
    //    return 0;
    // }
    if ( path == NULL || strlen(path) == 0 ) {
        memset(session->virtual_cwd, 0, PATH_MAX);
        session->virtual_cwd[0] = '/';
        session->cwd_id = vf_get_id_by_path_user(session->conn,session->virtual_cwd,session->user_name);
        cmd_ls(session);
    }
    if ( normalize_virtual_path(session->virtual_cwd, path, abs_path, sizeof(abs_path)) != 0 ) {
        //printf("路径规范化失败: %s\n", path);
        tlv_t* empty_tlv = tlv_create((uint8_t)INVALID_DIR, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);

        return -1;
    }

    int id = vf_get_id_by_path_user(session->conn, abs_path, session->user_name);
    if ( id > 0 ) {
        session->cwd_id = id;
        strncpy(session->virtual_cwd, abs_path, sizeof(session->virtual_cwd) - 1);
        session->virtual_cwd[sizeof(session->virtual_cwd) - 1] = 0;
        tlv_t* empty_tlv = tlv_create((uint8_t)CMD_SUCCESS, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        //printf("切换目录成功: %s\n", abs_path);
    }
    else {
        tlv_t* empty_tlv = tlv_create((uint8_t)INVALID_DIR, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        //printf("目录不存在: %s\n", abs_path);
    }
    return 0;
}

// ls命令
int cmd_ls(Session_t* session) {
    char abs_path[256];
    char file_name_arr[4096];
    int target_id;
    char* user_name = session->user_name;

    // 1.处理路径，如果path为NULL或者空字符串，列出当前目录
        target_id = session->cwd_id;
        strncpy(abs_path, session->virtual_cwd, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = '\0';
    
    int file_count = 0;     // 统计查询到的目录和文件数量
    VirtualFileInfo_t* infos = vf_list_by_parent_id(session->conn, target_id, session->user_name, &file_count);
    if ( file_count == 0 ) {
        tlv_t* empty_tlv = tlv_create((uint8_t)CMD_SUCCESS, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        //printf("该目录下无文件或子目录\n");
    }
    else {
        printf("目录%s下文件和目录:\n", abs_path);
        file_name_arr[0] = '\0';
        for ( int i = 0; i < file_count; i++ ) {
            if ( strcmp(infos[i].file_type, "d") == 0 ) {
                size_t curr_len = strlen(file_name_arr);
                snprintf(file_name_arr+curr_len, sizeof(file_name_arr) - curr_len, "#%s", infos[i].file_name);
            }
            else if ( strcmp(infos[i].file_type, "f") == 0 ) {
                size_t curr_len = strlen(file_name_arr);
                snprintf(file_name_arr + curr_len , sizeof(file_name_arr) - curr_len, "$%s", infos[i].file_name);
            }
        }
        file_name_arr[strlen(file_name_arr)] = '\0';
        tlv_t* ls_tlv = tlv_create((uint8_t)CMD_SUCCESS, file_name_arr, strlen(file_name_arr)+1);
        tlv_send(session->netfd, ls_tlv);
        tlv_free(ls_tlv);
    }
    if ( infos )   free(infos);

    return 0;
}

// mkdir命令
int cmd_mkdir(Session_t* session, const char* path) {
    // 1. 合法性检查：不能为空，不能带斜杠，不能为"."或".."
    /*if ( !path || strlen(path) == 0 || strchr(path, '/') || strcmp(path, ".") == 0 || strcmp(path, "..") == 0 ) {
        tlv_t empty_tlv = tlv_create((uint8_t)INVALID_DIR, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        return -1;
    }*/
    // 2. 检查当前目录下是否已存在同名目录
    if ( vf_exist_in_dir(session->conn, session->cwd_id, path, session->user_name, "dir") ) {
        tlv_t* empty_tlv = tlv_create((uint8_t)MKDIR_FAILED, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        return -1;
    }
    // 3. 构造虚拟路径
    char new_path[PATH_MAX];
    if ( strcmp(session->virtual_cwd, "/") == 0 )
        snprintf(new_path, sizeof(new_path), "/%s", path);
    else
        snprintf(new_path, sizeof(new_path), "%s/%s", session->virtual_cwd, path);
    // 4. 插入新目录
    VirtualFileInfo_t info = { 0 };
    strncpy(info.file_name, path, sizeof(info.file_name) - 1);
    strncpy(info.user_name, session->user_name, sizeof(info.user_name) - 1);
    info.parent_id = session->cwd_id;
    info.link = 0;
    strncpy(info.file_type, "dir", sizeof(info.file_type) - 1);
    strncpy(info.path, new_path, sizeof(info.path) - 1);

    if ( vf_insert(session->conn, &info) == 0 ) {
        tlv_t* empty_tlv = tlv_create((uint8_t)CMD_SUCCESS, NULL, 0);
        tlv_send(session->netfd, empty_tlv);
        tlv_free(empty_tlv);
        return 0;
    }
    /*else {
        printf("目录创建失败！\n");
        return -1;
    }*/
}

int cmd_remove(Session_t* session, const char* path){
    return 0;
}



// 8. trans函数



// 9. auth 函数
// 9.1生成盐值函数
int salt_maker(char *salt)
{
    int i, flag;
    srand(time(NULL) ^ (rand()<<16)); // 增加随机性
    salt[0] = '$';
    salt[1] = '6';
    salt[2] = '$';
    for (i = 3; i < SALT_LEN; ++i)
    {
        flag = rand() % 3;
        switch (flag)
        {
        case 0:
            salt[i] = rand() % 26 + 'a';
            break;
        case 1:
            salt[i] = rand() % 26 + 'A';
            break;
        case 2:
            salt[i] = rand() % 10 + '0';
            break;
        }
    }
    salt[SALT_LEN] = '\0';
    return 0;
}

// 9.2token

int token_maker(const char* key, const char* usr_name, char* token, size_t token_buf_len) {
    char* jwt = NULL;
    size_t jwt_length = 0;

    struct l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);

    params.alg = L8W8JWT_ALG_HS512;

    // strdup拷贝，最后记得free
    char* sub_copy = strdup(usr_name);
    params.sub = sub_copy;

    params.iat = time(NULL);
    params.exp = params.iat + 600; // 10分钟过期

    params.secret_key = (unsigned char*)key;
    params.secret_key_length = strlen(key);

    params.out = &jwt;
    params.out_length = &jwt_length;

    int r = l8w8jwt_encode(&params);

    free(sub_copy); // 释放

    if (r != L8W8JWT_SUCCESS) {
        printf("Token encode failed!\n");
        return -1;
    }
    if (jwt_length + 1 > token_buf_len) {
        printf("Token buffer too small!\n");
        l8w8jwt_free(jwt);
        return -2;
    }
    strcpy(token, jwt);
    l8w8jwt_free(jwt);
    return 0;
}


// 封装token校验函数，并提取token中的sub（用户名）

int token_validate(const char* key, const char* usr_name, const char* token, char* out_sub, size_t out_sub_len) {
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.alg = L8W8JWT_ALG_HS512;

    // 拷贝token字符串
    char* jwt_copy = strdup(token);
    params.jwt = jwt_copy;
    params.jwt_length = strlen(token);
    params.verification_key = (unsigned char*)key;
    params.verification_key_length = strlen(key);

    // 拷贝用户名
    char* sub_copy = strdup(usr_name);
    params.validate_sub = sub_copy;

    params.validate_exp = 1;
    params.exp_tolerance_seconds = 60;
    params.validate_iat = 1;
    params.iat_tolerance_seconds = 60;

    enum l8w8jwt_validation_result validation_result;
    
    // 修复1: 使用指针声明并初始化为NULL
    struct l8w8jwt_claim* claims = NULL;
    size_t claim_count = 0;

    // 修复2: 传递指针的地址 (&claims)
    int decode_result = l8w8jwt_decode(&params, &validation_result, &claims, &claim_count);

    free(jwt_copy);
    free(sub_copy);

    if (decode_result == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID) {
        // 提取sub
        int found_sub = 0;
        for (size_t i = 0; i < claim_count; ++i) {
            if (strcmp(claims[i].key, "sub") == 0) {
                strncpy(out_sub, claims[i].value, out_sub_len - 1);
                out_sub[out_sub_len - 1] = '\0';
                found_sub = 1;
                break;
            }
        }
        
        // 修复3: 使用后释放claims内存
        l8w8jwt_free_claims(claims, claim_count);
        
        if (!found_sub) {
            // 没有sub字段
            return -2;
        }
        return 0; // 验证通过
    }
    else {
        // 修复4: 即使失败也要释放可能分配的内存
        if (claims) {
            l8w8jwt_free_claims(claims, claim_count);
        }
        return -1; // 验证失败
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


//11. l8w8jwt
int encode(char *key, char *usr_name, char *token) {
    char* jwt;
    size_t jwt_length;

    struct l8w8jwt_encoding_params params;
    l8w8jwt_encoding_params_init(&params);

    params.alg = L8W8JWT_ALG_HS512;
    params.sub = usr_name;
    params.iat = time(NULL);
    params.exp = params.iat + 600; // 10分钟过期

    // 修复1：直接使用key计算长度
    params.secret_key = (unsigned char*)key;
    params.secret_key_length = strlen(key); // 使用原始key指针

    params.out = &jwt;
    params.out_length = &jwt_length;

    int r = l8w8jwt_encode(&params);
    
    // 修复2：添加缓冲区大小检查
    if (r == L8W8JWT_SUCCESS) {
        // 检查token缓冲区是否足够
        size_t jwt_strlen = strlen(jwt);
        if (jwt_strlen < MAX_TOKEN_SIZE) { // 假设MAX_TOKEN_SIZE是您的缓冲区大小
            strcpy(token, jwt);
        } else {
            // 处理缓冲区不足
            l8w8jwt_free(jwt);
            return -2;
        }
        l8w8jwt_free(jwt);
        return 0;
    } else {
        printf("Encoding failed: %d\n", r);
        return -1;
    }
}




int decode(char *key, char *usr_name, char *token){

        struct l8w8jwt_decoding_params params;
        l8w8jwt_decoding_params_init(&params);

        params.alg = L8W8JWT_ALG_HS512;

        params.jwt = token;
        params.jwt_length = strlen(token);    
        params.verification_key = (unsigned char*)key;
        params.verification_key_length = strlen(key);

        /* 
         * Not providing params.validate_iss_length makes it use strlen()
         * Only do this when using properly NUL-terminated C-strings! 
         */
        // params.validate_iss = "Black Mesa"; 
        params.validate_sub = usr_name;

        /* Expiration validation set to false here only because the above example token is already expired! */
        params.validate_exp = 1; 
        params.exp_tolerance_seconds = 60;

        params.validate_iat = 1;
        params.iat_tolerance_seconds = 60;

        enum l8w8jwt_validation_result validation_result;

        int decode_result = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

        if (decode_result == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID) 
        {
            printf("\n Example HS512 token validation successful! \n");
        }
        else
        {
            printf("\n Example HS512 token validation failed! \n");
            return EXIT_FAILURE;
        }
    
        /*
         * decode_result describes whether decoding/parsing the token succeeded or failed;
         * the output l8w8jwt_validation_result variable contains actual information about
         * JWT signature verification status and claims validation (e.g. expiration check).
         * 
         * If you need the claims, pass an (ideally stack pre-allocated) array of struct l8w8jwt_claim
         * instead of NULL,NULL into the cortonding l8w8jwt_decode() function parameters.
         * If that array is heap-allocated, remember to free it yourself!
         */

        return 0;
    }


    // 临时方案
void sig_handler1(int signum) {}
void sig_handler2(int signum) {}
int cmd_upload(Session_t* session, const char* filename) { return 0; }
int cmd_download(Session_t* session, const char* filename) { return 0; }
