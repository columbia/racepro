#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

#define FILE  "/tmp/signal2.out"
int fd;

void sighand(int sig)
{
	char *str = "signal handler\n";
	write(fd, str, strlen(str));
}

main()
{
	char buf[128];
	int ret;

	unlink(FILE);
	fd = open(FILE, O_RDWR | O_CREAT | O_EXCL , 0644);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	signal(SIGHUP, sighand);
	sprintf(buf, "%s\n", "before");
	ret = write(fd, buf, strlen(buf));
	ret = usleep(20000000);
	sprintf(buf, "%s (%d)\n", "after", ret);
	ret = write(fd, buf, strlen(buf));

	exit(0);
}
