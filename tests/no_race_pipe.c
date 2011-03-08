#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/no_race.out"

main()
{
        int pipefd[2];
        char buf[16];
	int fd;
	int ret;

        if(pipe(pipefd) < 0) {
                perror("pipe");
                exit(1);
        }

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
                close(pipefd[1]);
                read(pipefd[0], buf, sizeof buf);
                close(pipefd[0]);

                memset(buf, 'C', sizeof buf);
                printf("child writes after read from pipe\n");
                write(fd, buf, sizeof buf); // no race
                break;
        default:
                memset(buf, 'P', sizeof buf);
                printf("parent writes\n");
                write(fd, buf, sizeof buf); // no race

                close(pipefd[0]);
                write(pipefd[1], buf, sizeof buf);
                close(pipefd[1]);

                wait(NULL);
        }
        close(fd);
	exit(0);
}
