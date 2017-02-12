#ifndef _COMMON_H_
#define _COMMON_H_
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

#define MODE_CLIENT 1
#define MODE_SERVER 2

int verbose;
int sleptime;
long int totalsend;
long int mpersec;

struct attackinfo{
	long dstipaddr;
	long srcipaddr;
	unsigned short port;
	int pkglen;
	int bw;
	char *buff;
}; 

int setpkg(struct attackinfo *para);
int chkrate(struct timeval *last,long int bwl,int pkglen);
#endif

