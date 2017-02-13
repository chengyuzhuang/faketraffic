/*
 本程序作为大带宽用户打量使用
*/
#define USAGE "Usage: %s [-v] -[s source ip addre] [-d dest ip address] [-l PACKET_LENGTH_IN_BYTES] [-b BANDWIDTH_IN_MEGA_BYTES_PER_SEC] -[p PORT]\n"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>/* close() */
#include <string.h> /* memset() */
#include <sys/time.h>/*gettimeofday*/
#include <time.h>/*nanosleep*/
#include "common.h"

int main(int argc, // Number of strings in array argv
		char *argv[], // Array of command-line argument strings
		char **envp) { // Array of environment variable strings

	const char *localhost="127.0.0.1";
	char *srcipaddr = "127.0.0.1";
	char *dstipaddr = NULL;
	int plen = 100;
	double bwm = 1.0;
	double bw=100.0;
	int port = 5556;
	verbose=0;
	sleptime=0;
	totalsend=0;
	if(argc==1){
		printf(USAGE,argv[0]);
		exit(0);
	}
	char c;
	printf("================================================\n");
	printf("IP TRAFFIC GENERATOR, written by steven@gp2p.com\n");
	while (1) {
		if ((c = getopt(argc, argv, "s:p:l:b:d:v")) == EOF)
			break;
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 's':
			srcipaddr= optarg;
			break;
		case 'l':
			plen = atol(optarg);
			if(plen>4096){
				fprintf(stderr,"packet is too big\n");
				exit(0);
			}
			break;
		case 'b':
			bwm = atof(optarg);/*it is mbits/s*/
			bw=bwm*1000*1000/8;/*convert into bytes*/
			break;
		case 'p':
			port= atol(optarg);
			break;
		case 'd':
			dstipaddr=optarg;
			break;
		default:
			printf(USAGE, argv[0]);
			printf("================================================\n");
			return EXIT_FAILURE;
		}
	}

	if(dstipaddr==NULL){
		printf("Please give me a legal ip address\n");
		exit(0);
	}
	if(port==0){
		printf("You forgot give me the port\n");
		exit(0);
	}	
	
	int sock;
	struct sockaddr_in sa;
	int total = plen;
	struct attackinfo attack;

	attack.dstipaddr=inet_addr(dstipaddr);
	attack.srcipaddr=inet_addr(srcipaddr);
	attack.port=port;
	attack.pkglen=plen;
	attack.bw=bw;
	//Prepare buffer
	int i;
	char buff[MAX_PACKET_SIZE];
	for(i=0;i<MAX_PACKET_SIZE;i++){
		buff[i]=1;
	}
	//memset(buff,0,MAX_PACKET_SIZE);
	attack.buff=buff;

	// Temp var for loop
	//not using localhost,just act like ddos
	if(inet_addr(localhost)!=inet_addr(srcipaddr)){
		//here we need to make a raw socket
		sock=setpkg(&attack);
	}

	// Create socket
	else{
		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

	if (-1 == sock){ /* if socket failed to initialize, exit */
		printf("Error creating socket.\n");
		exit(EXIT_FAILURE);
	}


	ssize_t bytes_sent=0;
	int num = 1;
	struct timeval last;
	gettimeofday(&last,NULL);

	printf("SENDING...\n");

	memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(dstipaddr);
        sa.sin_port = htons(port);
	mpersec=0;
	while(1) {
		if (verbose) {
			printf(
			"SENDING PACKET SEQ#[%d] LENGTH [%d]BYTES BANDWIDTH [%0.2f]Mb/s\n",num,plen,bwm);
		}
		bytes_sent = sendto(sock, buff, total, 0, (struct sockaddr*) &sa,
				sizeof sa);
		num++;
		totalsend+=bytes_sent;
		chkrate(&last,bw-totalsend,plen);
		
		if (bytes_sent < 0) {
			fprintf(stderr, "Error sending packet.\n");
			close(sock);
			exit(EXIT_FAILURE);
		}
	}
	return EXIT_SUCCESS;

}
