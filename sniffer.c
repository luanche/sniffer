#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
//#include <linux/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

unsigned char buffer[2048];

void num2p(int num, char *prot){//TCP和UDP协议端口号转协议类型
    switch (num)
    {
    case 7:
        strcpy(prot,"echo");
        break;
    case 15:
        strcpy(prot,"netstat");
        break;
    case 21:
        strcpy(prot,"ftp");
        break;
    case 22:
        strcpy(prot,"ssh");
        break;
    case 23:
        strcpy(prot,"telnet");
        break;
    case 25:
        strcpy(prot,"smtp");
        break;
    case 37:
        strcpy(prot,"time");
        break;
    case 53:
        strcpy(prot,"dns");
        break;
    case 57:
        strcpy(prot,"mtp");
        break;
    case 69:
        strcpy(prot,"tftp");
        break;
    case 80:
        strcpy(prot,"http");
        break;
    case 110:
        strcpy(prot,"pop3");
        break;
    case 179:
        strcpy(prot,"bgp");
        break;
    case 443:
        strcpy(prot,"https");
        break;
    case 1521:
        strcpy(prot,"oracle");
        break;
    case 1900:
        strcpy(prot,"ssdp");
        break;
    case 3306:
        strcpy(prot,"mysql");
        break;
    default:
        strcpy(prot,"");
        break;
    }
}


void analyse_udp(unsigned char *udphead){//UDP协议分析函数
    printf("UDP:\n");
    int sport=(udphead[0]<<8)+udphead[1];
    int dport=(udphead[2]<<8)+udphead[3];
    printf("  源端口: %d ",sport);
    char udp_sprot[10]={};
    char udp_dprot[10]={};
    num2p(sport,udp_sprot);
    if(strlen(udp_sprot)) printf("(%s) ",udp_sprot);
    printf(", ");
    printf("目的端口: %d ",dport);
    num2p(dport,udp_dprot);
    if(strlen(udp_dprot)) printf("(%s) ",udp_dprot);
    printf("\n");
}

void analyse_tcp(unsigned char *tcphead){//TCP协议分析函数
    printf("TCP:\n");
    int sport=(tcphead[0]<<8)+tcphead[1];
    int dport=(tcphead[2]<<8)+tcphead[3];
    printf("  源端口: %d ",sport);
    char tcp_sprot[10]={};
    char tcp_dprot[10]={};
    num2p(sport,tcp_sprot);
    if(strlen(tcp_sprot)) printf("(%s) ",tcp_sprot);
    printf(", ");
    printf("目的端口: %d ",dport);
    num2p(dport,tcp_dprot);
    if(strlen(tcp_dprot)) printf("(%s) ",tcp_dprot);
    printf("\n");
    int urg,ack,psh,rst,syn,fin;
    int flag=tcphead[13] % 0b1000000;
    //获取标志位，URG ACK PSH RST SYN FIN
    urg=flag/0b100000;flag=flag%0b100000;
    ack=flag/0b10000 ;flag=flag%0b10000 ;
    psh=flag/0b1000  ;flag=flag%0b1000  ;
    rst=flag/0b100   ;flag=flag%0b100   ;
    syn=flag/0b10    ;flag=flag%0b10    ;
    fin=flag;
    printf("  标志位: ");
    if(urg) printf("URG ");
    if(ack) printf("ACK ");
    if(psh) printf("PSH ");
    if(rst) printf("RST ");
    if(syn) printf("SYN ");
    if(fin) printf("FIN ");
    printf("\n");
    //获取序号和确认号
    unsigned long SEQ=0,ACK=0;
    int i;
    for(i=0;i<3;i++){
        SEQ+=tcphead[i+4];
        SEQ=SEQ<<8;
        ACK+=tcphead[i+8];
        ACK=ACK<<8;
    }
    SEQ+=tcphead[i+4];
    ACK+=tcphead[i+8];
    printf("  seq: %lu ",SEQ);
    if(ack) printf(", ack: %lu \n",ACK);
    else printf("\n");

}

void analyse_icmp(unsigned char *icmphead){//ICMP协议分析函数
    printf("ICMP: \n");
    unsigned int type,code;
    type = icmphead[0];//类型
    code = icmphead[1];//代码
    printf("  类型: %d ",type);
    if(type == 8){
        printf("(Echo (ping) 请求) , 代码: %d  \n",code);
    }else if(type == 0){
        printf("(Echo (ping) 响应) , 代码: %d  \n",code);
    }else if(type == 3){
        printf("(目标不可达) , 代码: %d ",code);
        if(code == 0){
            printf("(网络不可达) \n");
        }else if(code == 1){
            printf("(主机不可达) \n");
        }else if(code == 2){
            printf("(协议不可达) \n");
        }else if(code == 3){
            printf("(端口不可达) \n");
        }else{
            printf("\n");
        }
    }else if(type == 11){
        printf("(TTL超时) , 代码: %d \n",code);
    }else{
        printf(", 代码: %d \n",code);
    }
}

void analyse_igmp(unsigned char *igmphead){//IGMP协议分析函数
    printf("IGMP: \n");
}

void analyse_ip(unsigned char *iphead){//IP协议分析函数
    if(iphead[0] / 0x10 == 4){//IPv4，IP版本号
        int lenth = (iphead[0] % 0x10)*4;//首部长度
        printf("IPv4: \n");
        printf("  源IP: %d.%d.%d.%d , ",iphead[12],iphead[13],iphead[14],iphead[15]);
        printf("目的IP: %d.%d.%d.%d \n",iphead[16],iphead[17],iphead[18],iphead[19]);
        printf("  TTL: %d , 首部长度: %dByte \n",iphead[8],lenth);
        //根据协议id调用内层协议分析函数
        if(iphead[9]==6) analyse_tcp(iphead+lenth);
        else if(iphead[9]==17) analyse_udp(iphead+lenth);
        else if(iphead[9]==1) analyse_icmp(iphead+lenth);
        else if(iphead[9]==2) analyse_igmp(iphead+lenth);
        else printf("  协议id: %d\n",iphead[9]);
    }else{
        printf("  IP版本: %d\n",iphead[0] / 0x10);
        return ;
    }
}

void analyse_arp(unsigned char *arphead){//ARP协议分析函数
    printf("ARP: \n");
    unsigned int opcode = (arphead[6]<<8)+arphead[7];//操作码
    printf("  操作类型: %d ",opcode);
    if(opcode == 1){
        printf("(ARP请求) \n");
        printf("  描述: Who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n",
            arphead[24],arphead[25],arphead[26],arphead[27],
            arphead[14],arphead[15],arphead[16],arphead[17]
        );
    }else if(opcode == 2){
        printf("(ARP应答) \n");
        printf("  描述: %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
            arphead[14],arphead[15],arphead[16],arphead[17],
            arphead[8],arphead[9],arphead[10],arphead[11],arphead[12],arphead[13]
        );
    }else{
        printf("\n");
    }
} 

void analyse_eth(unsigned char *ethhead){//以太网帧协议分析函数
    printf("Ethernet:\n");
    printf("  源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x , ",ethhead[6],ethhead[7],ethhead[8],ethhead[9],ethhead[10],ethhead[11]);
    printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",ethhead[0],ethhead[1],ethhead[2],ethhead[3],ethhead[4],ethhead[5]);
    int eth_type = (ethhead[12]<<8)+ethhead[13];//下层协议类型
    printf("  类型: 0x%04x\n",eth_type);
    if(eth_type == 0x0800)//IP协议
        analyse_ip(ethhead+14);
    else if(eth_type == 0x0806)//ARP协议
        analyse_arp(ethhead+14);
}


int main(int argc, char **argv){
    int sock,n;
    struct ip *ip;
    struct ifreq ethreq;
    int no=0;
    //设置原始套接字方式为接收所有数据包
    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
        perror("原始套接字建立失败\n");
        exit(1); 
    }
    //设置网卡工作方式为混杂模式
    strncpy(ethreq.ifr_name,"ens160",IFNAMSIZ);
    if(ioctl(sock,SIOCGIFFLAGS,&ethreq)==-1){
        perror("设置混杂工作模式失败\n");
        close(sock);
        exit(1);
    }
    ethreq.ifr_flags|=IFF_PROMISC;
    if(ioctl(sock,SIOCSIFFLAGS,&ethreq)==-1){
        perror("设置混杂工作模式失败\n");
        close(sock);
        exit(1);
    }
    //开始捕获数据并进行简单分析
    char ch;
    char proto[6]={},
         saddr[20]={},
         daddr[20]={},
         address[20]={};
    int addrnum = 0;
    int slen = 0;

    while((ch = getopt(argc, argv, "p:s:d:h")) != -1){//参数捕获
        switch (ch) {
            case 'p':
                slen = strlen(optarg);
                if(slen > 5){
                    fprintf(stdout, "协议类型错误\n");
                    return -1;
                }
                memcpy(proto, optarg, slen);
                proto[slen] = '\0';
                break;
            case 's':
                slen = strlen(optarg);
                if(slen > 15 || slen < 7){
                    fprintf(stdout, "源IP地址格式错误\n");
                    return -1;
                }
                memcpy(saddr, optarg, slen);
                saddr[slen] = '\0';
                break;
            case 'd':
                slen = strlen(optarg);
                if(slen > 15 || slen < 7){
                    fprintf(stdout, "目标IP地址格式错误\n");
                    return -1;
                }
                memcpy(daddr, optarg, slen);
                saddr[slen] = '\0';
                break;
            case 'h':
                fprintf(stdout, "usage: snffer [-p 协议] [-s 源IP地址] [-d 目标IP地址]\n"
                                "    -p    协议[tcp/udp/icmp/igmp/arp]\n"
                                "    -s    源IP地址 address\n"
                                "    -d    目标IP地址 address\n");
                exit(0);
            case '?':
                fprintf(stdout, "无法识别参数: %c\n", ch);
                exit(-1);
        }
    }
    
    while(1){
        n = recvfrom(sock,buffer,2048,0,NULL,NULL);
        if(strlen(proto)){
            if(strcmp(proto, "tcp\0")==0){//根据协议过滤
                if(buffer[23] != 6)
                    continue;
                else 
                    goto addr;
            }else if(strcmp(proto, "udp\0")==0){
                if(buffer[23] != 17)
                    continue;
                else 
                    goto addr;
            }else if(strcmp(proto, "icmp\0")==0){
                if(buffer[23] != 1)
                    continue;
                else
                    goto addr;
            }else if(strcmp(proto, "igmp\0")==0){
                if(buffer[23] != 2)
                    continue;
                else
                    goto addr;
            }else if(strcmp(proto, "arp\0")==0){
                if(((buffer[12]<<8)+buffer[13]) != 0x0806)
                    continue;
                else
                    goto start;
            }
        }

addr:
        if(strlen(saddr)){//根据源地址过滤
            if(buffer[14] / 0x10 != 4)
                continue;
            sprintf(address,"%d.%d.%d.%d",(int)buffer[26],(int)buffer[27],(int)buffer[28],(int)buffer[29]);

            if(strcmp(address, saddr) != 0)
                continue;
        }
        if(strlen(daddr)){//根据目标地址过滤
            if(buffer[14] / 0x10 != 4)
                continue;
            sprintf(address,"%d.%d.%d.%d",buffer[30],buffer[31],buffer[32],buffer[33]);
            if(strcmp(address, saddr) != 0)
                continue;
        }
start:
        no++;
        printf("\n\n---- 第%d个:%d字节 ----\n",no,n);
        //检查包是否包含了至少完整的以太帧(14)，IP(20)和TCP/UDP(8)包头
        if(n<42){
            perror("recvfrom():");
            printf("不完整以太网帧 (errno: %d)\n",errno);
            close(sock);
            exit(0);
        }
        analyse_eth(buffer);//调用以太网桢分析函数
    }
    
    return 0;
}