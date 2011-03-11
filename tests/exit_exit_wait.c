#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/exit-exit-wait.out"

main()
{
        char buf[16];
	int fd;
	int ret;

	unlink(FILE);
	fd = open(FILE, O_RDWR | O_CREAT | O_EXCL , 0);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	ret = fork();
        if(ret < 0) {
		perror("fork");
		exit(1);
        }
        
        if(ret == 0) {
                memset(buf, 'C', sizeof buf);
                printf("child writes\n");
                write(fd, buf, sizeof buf);
                close(fd);
                exit(0);
        }

        ret = fork();
        if(ret < 0) {
                perror("fork");
                exit(1);
        }

        if(ret == 0) {
                close(fd);
                exit(0);
        }

        wait(NULL);

        memset(buf, 'P', sizeof buf); 
        printf("parent writes\n");
        write(fd, buf, sizeof buf);

        wait(NULL);

	exit(0);
}
