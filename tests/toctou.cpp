#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    if (access("test.dir/test.txt", W_OK) != 0) {
	return 0;
    }

    chmod ("test.dir/test.txt", 00777);
}
