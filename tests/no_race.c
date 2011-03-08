#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/no_race.out"

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

	ret = fork();
        switch(ret) {
        case -1:
		perror("fork");
		exit(1);
        case 0:
                memset(buf, 'C', sizeof buf);
                printf("child writes\n");
                write(fd, buf, sizeof buf); // no race
                break;
        default:
                wait(NULL);
                printf("parent writes after child return\n");
                write(fd, buf, sizeof buf); // no race
        }
        close(fd);
	exit(0);
}
