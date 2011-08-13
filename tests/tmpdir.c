#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

main()
{
	int ret;

	ret = fork();
	if (ret < 0) {
		perror("fork");
		exit(1);
	} else if (ret == 0) {
		usleep(300);
		creat("/tmp/tmpdirfile", 0666);
		usleep(300);
	} else {
		usleep(300);
		creat("/tmp/tmpdirfile", 0666);
		usleep(300);
	}

	exit(0);
}
