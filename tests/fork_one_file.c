#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/fork_one_file.out"

main()
{
	char *str;
	int fd;
	int ret;

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
		str = "child\n";
		usleep(10);
	} else {
		str = "parent\n";
	}

	ret = write(fd, str, strlen(str));
	if (ret < 0) {
		perror("write");
		exit(1);
	}

	exit(0);
}
