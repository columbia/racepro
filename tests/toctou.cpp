#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    if (access("test.txt", W_OK) != 0) {
	return 0;
    }

    chmod ("test.txt", 00777);
}
