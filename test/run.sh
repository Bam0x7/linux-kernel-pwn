#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -no-reboot \
    -kernel "./bzImage" \
    -append "console=ttyS0 qiet loglevel=3 oops=panic panic=-1 nokaslr pti=on" \
    -monitor /dev/null \
    -initrd "./rootfs_updated.cpio" \
    -cpu qemu64,+smep,+smap \
    -smp cores=1
