/*
** gcc -g ethEncapRecv.c -o ethEncapRecv
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h> //#include <linux/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

union ethframe
{
    struct
    {
        struct ethhdr header;
        char data[ETH_DATA_LEN];
    } field;
    char buffer[ETH_FRAME_LEN];
};

int main(int argc, char **argv)
{

    int sock, n;
    struct ifreq ethreq;
    // 设置原始套接字方式为接收所有数据包
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("原始套接字建立失败\n");
        exit(1);
    }
    // 设置网卡工作方式为混杂模式
    strncpy(ethreq.ifr_name, "eth0", IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1)
    {
        perror("设置混杂工作模式失败\n");
        close(sock);
        exit(1);
    }
    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1)
    {
        perror("设置混杂工作模式失败\n");
        close(sock);
        exit(1);
    }
    // 开始捕获数据并进行简单分析
    unsigned char dest[20] = "00:11:22:33:44:55";    // 目的主机MAC
    unsigned char sourceA[20] = "00:11:22:11:11:aa"; // 主机A源MAC
    unsigned char sourceB[20] = "00:11:22:11:11:bb"; // 主机B源MAC
    unsigned char temp[20] = {};
    while (1)
    {
        union ethframe frame;
        n = recvfrom(sock, frame.buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if (n < 46)
        {
            close(sock);
            continue;
        }
        unsigned char *destp = frame.field.header.h_dest;
        sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x", destp[0], destp[1], destp[2], destp[3], destp[4], destp[5]);
        if (strcmp(temp, dest) != 0)
            continue;

        unsigned char *source, *data;
        source = frame.field.header.h_source;
        sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x", source[0], source[1], source[2], source[3], source[4], source[5]);
        data = frame.field.data;
        if (strcmp(temp, sourceA) == 0)
        {
            printf("收到来自主机A( %s )的消息：", temp);
            for (int i = 0; data[i] != 0x00; i++)
            {
                printf("%c", data[i]);
            }
            printf("\n\n");
        }
        else if (strcmp(temp, sourceB) == 0)
        {
            printf("收到来自主机B( %s )的消息：", temp);
            for (int i = 0; data[i] != 0x00; i++)
            {
                printf("%c", data[i]);
            }
            printf("\n\n");
        }
        else
        {
            continue;
        }
    }

    return 0;
}
