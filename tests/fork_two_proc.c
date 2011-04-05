#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/fork_two_fork.out"

main()
{
	char *str;
	int who;
	int fd;
	int ret;
	char buf[16];

	unlink(FILE);
	fd = open(FILE, O_RDWR | O_CREAT | O_EXCL , 0644);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	ret = fork();
	if (ret < 0) {
		perror("fork");
		exit(1);
	} else if (ret == 0) {
		who = 2;
		str = "child2\n";
		usleep(100);
	} else {
		ret = fork();
		if (ret < 0) {
			perror("fork");
			exit(1);
		} else if (ret == 0) {
			who = 1;
			str = "child1\n";
			usleep(50);
		} else {
			who = 0;
			str = "parent\n";
		}
	}

	ret = write(fd, str, strlen(str));
	if (ret < 0) {
		perror("write");
		exit(1);
	}

	if (who == 0) {
		ret = waitpid(0, NULL, 0);
		sprintf(buf, "wait %d\n", ret);
		ret = write(fd, buf, strlen(str));

		ret = waitpid(0, NULL, 0);
		sprintf(buf, "wait %d\n", ret);
		ret = write(fd, buf, strlen(str));
	}

	exit(0);
}
