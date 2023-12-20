/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <iostream>
#include <fstream>

using namespace std;

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 4096 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
    string addr, protocol, host, port, path;

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    
    addr = argv[1];
    protocol = addr.substr(0, addr.find("//") - 1);
	addr = addr.substr(addr.find("//") + 2);
	if (addr.find('/') == addr.npos) path = "/";
	else path = addr.substr(addr.find('/'));
	host = addr.substr(0, addr.find('/'));
	if (host.find(':') != host.npos) {
		port = host.substr(host.find(':') + 1);
		host = host.substr(0, host.find(':'));
	}
	else port = "80";


	if ((rv = getaddrinfo(host.data(), port.data(), &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure
	
	cout << host << ' ' << port << ' ' << path << endl;
	
    string request = "GET " + path + " HTTP/1.1\r\n" + "User-Agent: Wget/1.12(linux-gnu)\r\n" +
	  				 "Host: " + host + ":" + port + "\r\n" + "Connection: Keep-Alive\r\n\r\n";


	send(sockfd, request.c_str(), request.size(), 0);

	ofstream out;
    out.open("output", ios::binary);
    bool header = true;
	long total_bytes = 0;
    while (true) {
        memset(buf, '\0', MAXDATASIZE);
        numbytes = recv(sockfd, buf, MAXDATASIZE, 0);
        if (numbytes > 0) {
			// cout << numbytes << endl;
			total_bytes += numbytes;
            if (header) {
				cout << buf << endl;
                char* head = strstr(buf, "\r\n\r\n");
				// cout << head << endl;
				if (head != NULL){
					head+=4;
					header = false;
				}
                out.write(head, numbytes - 19);
				// printf("strlen(head): %ld", strlen(head) );
				// printf("numbytes head %d", numbytes);
            } 
			else out.write(buf, sizeof(char) * numbytes);
        } 
		else break;
    }

	out.close(); 
	printf("total bytes: %ld", total_bytes);

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}

	// buf[numbytes] = '\0';

	// printf("client: received '%s'\n",buf);

	close(sockfd);

	return 0;
}

