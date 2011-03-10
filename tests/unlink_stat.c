#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

main() {
        int fd, ret;
        const char* path = "/tmp/unlink_stat.out";
        struct stat st;

        if((fd = creat(path, 0777)) < 0) {
                perror("creat");
                exit(1);
        }
        write(fd, path, strlen(path));
        close(fd);

        ret = fork();
        switch(ret) {
        case -1:
                perror("fork");
                exit(1);
        case 0:
                if(stat(path, &st) < 0)
                        printf("ERROR: file not there!\n");
                else
                        printf("file still there\n");
                break;
        default:
                usleep(10);
                unlink(path);
                wait(NULL);
        }
        
}



