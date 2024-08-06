#!/bin/sh
gcc -o exploit exploit.c -static $1
mv ./exploit ./initramfs/home/user
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs_update.cpio
mv ./initramfs_update.cpio ../
