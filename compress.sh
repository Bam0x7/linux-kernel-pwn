#!/bin/sh
gcc exp.c -o exp -static $1
mv exp rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
