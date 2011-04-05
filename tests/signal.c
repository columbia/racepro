#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/signal.out"
int fd;

void sighand(int sig)
{
	char *str = "signal handler\n";
	write(fd, str, strlen(str));
}

main()
{
	char buf[128];
	char *str;
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
		signal(SIGHUP, sighand);
		sprintf(buf, "%s\n", "child before");
		ret = write(fd, buf, strlen(buf));
		ret = usleep(2000000);
		sprintf(buf, "%s (%d)\n", "child after", ret);
		ret = write(fd, buf, strlen(buf));
	} else {
		str = "parent\n";
		sleep(1);
		kill(ret, SIGHUP);
	}

	ret = write(fd, str, strlen(str));
	if (ret < 0) {
		perror("write");
		exit(1);
	}

	exit(0);
}
