all:
	gcc test.c md5_count.c -o test -lssl -lcrypto

