#include <sys/un.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int test_connect() {
	struct sockaddr_un addr;
	char data[256] = "test connection";
	int fd;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("creating socket");
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sun_path, "/tmp/test.sock");
	addr.sun_family = AF_UNIX;
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr.sun_path)) < 0 ) {
		perror("connect error");
		return 1;
	}
	if (write(fd, data, strlen(data) + 1) < 0) {
		perror("writing data");
		return 1;
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv) {
	int ret;
	if (argc < 2) { 
		perror("missing syscall to test");
		exit(EXIT_FAILURE);
	}
	printf("Test syscall: %s \n",  argv[1]);
	if (strcmp( argv[1],"connect") == 0)
		ret = test_connect();
	else {
		perror("syscall not supported");	
		exit(EXIT_FAILURE);
	}
	if (ret != 0)
		exit(EXIT_FAILURE);
}
