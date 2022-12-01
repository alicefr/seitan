#include <sys/un.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main( int argc, char *argv[] ) {
	struct sockaddr_un addr;
	int fd, connfd,n, addrlen;
	char sock_path[] = "/tmp/test.sock";
	char buffer[256];
	unlink(sock_path);
	addrlen = sizeof(addr);
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("creating socket");
		return 1;
	}        
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sun_path, sock_path);
	addr.sun_family = AF_UNIX;
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("binding");
		exit(EXIT_FAILURE);
	}

	listen(fd,5);
	if ((connfd = accept(fd, (struct sockaddr *)&addr, (socklen_t*)&addrlen)) < 0) {
		perror("ERROR on accept");
		exit(EXIT_FAILURE);
	}

	bzero(buffer,256);
	n = read(connfd,buffer,255 );

	if (n < 0) {
		perror("ERROR reading from socket");
		exit(EXIT_FAILURE);
	}

	printf("%s\n",buffer);
	unlink(sock_path);
	close(fd);
	return 0;
}
