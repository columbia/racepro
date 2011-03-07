#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/read-write-write.out"

main()
{
        char buf[16];
	int fd;
	int ret;

        memset(buf, 'X', sizeof buf);

	unlink(FILE);
	fd = open(FILE, O_RDWR | O_CREAT | O_EXCL , 0);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
        write(fd, buf, sizeof buf);
        lseek(fd, 0, SEEK_SET);

	ret = fork();
        switch(ret) {
        case -1:
		perror("fork");
		exit(1);
        case 0:
                memset(buf, 'C', sizeof buf);
                printf("child writes\n");
                write(fd, buf, sizeof buf);
                break;
        default:
                printf("parent reads\n");
                read(fd, buf, sizeof buf);
                memset(buf, 'P', sizeof buf); 
                lseek(fd, 0, SEEK_SET);
                printf("parent writes\n");
                write(fd, buf, sizeof buf);
        }
        close(fd);
	exit(0);
}
