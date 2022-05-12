hello_ll: hello_ll.c
	gcc -Wall hello_ll.c `pkg-config fuse3 --cflags --libs` -o hello_ll

.PHONY: run umount unix

run:
	sudo strace -f ./hello_ll ./test

unix:
	gcc -Wall first.c -o first
	gcc -Wall second.c -o second

umount:
	sudo umount ./test || true
	sudo rm -f /tmp/fuse_uds
