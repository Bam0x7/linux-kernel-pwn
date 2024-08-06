#!/bin/sh
gcc fuzz2.c -o fuzz2 -D_FILE_OFFSET_BITS=64 -lfuse -static $1
mv ./fuzz2 ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
