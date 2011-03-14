#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static int toeuid = 1000;

void *thread_func(void *arg) {
        printf("t2: euid=%d\n", geteuid());
        usleep(10);
        printf("t2: euid=%d\n", geteuid());
}

void *euid_thread(void *arg) {
        usleep(10);
        seteuid(toeuid);
        printf("t1: euid=%d\n", geteuid());
}


main()
{
        pthread_t t1, t2;
        if(pthread_create(&t1, NULL, euid_thread, NULL) < 0) {
                perror("pthread_create");
                exit(1);
        }
        if(pthread_create(&t2, NULL, thread_func, NULL) < 0) {
                perror("pthread_create");
                exit(1);
        }
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        printf("t0: euid=%d\n", geteuid());
}
