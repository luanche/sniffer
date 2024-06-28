/*
** gcc -g ethEncapSend.c -o ethEncapSend -lpthread -lm
*/

#include <stdio.h>           //memcpy()
#include <string.h>          //strxxx()
#include <unistd.h>          //close(),sleep()
#include <sys/socket.h>      //socket()
#include <arpa/inet.h>       //htons()
#include <linux/if.h>        //struct ifreq
#include <linux/if_ether.h>  //ETH_ALEN(6),ETH_HLEN (14),ETH_FRAME_LEN (1514),struct ethhdr
#include <linux/if_packet.h> //struct sockaddr_ll
#include <sys/ioctl.h>       //ioctl()

#include <pthread.h> //pthread_create(),pthread_join()
#include <math.h>    //pow()
#include <stdlib.h>  //rand()
#include <time.h>    //time()

union ethframe
{
    struct
    {
        struct ethhdr header;
        char data[ETH_DATA_LEN];
    } field;
    unsigned char buffer[ETH_FRAME_LEN];
};

union ethframe frameA;
union ethframe frameB;
unsigned int frame_lenA;
unsigned int frame_lenB;
char dataA[1502] = {0x00}; // A发送的数据
char dataB[1502] = {0x00}; // B发送的数据

char sourceA[ETH_ALEN] = {0x00, 0x11, 0x22, 0x11, 0x11, 0xaa}; // 主机A源MAC
char sourceB[ETH_ALEN] = {0x00, 0x11, 0x22, 0x11, 0x11, 0xbb}; // 主机B源MAC
char dest[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};    // 目的主机MAC
short protoA = 0xffaa;                                         // 主机A使用协议号
short protoB = 0xffbb;                                         // 主机B使用协议号

pthread_t idA, idB; // 线程号
pthread_t Bus = 0;
int sendtimes;

unsigned int encapEth(char *source, char *dest, short proto, char *data, union ethframe *frame)
{ // 封装以太网帧
    unsigned short data_len = strlen(data);
    if (data_len < 46)
        data_len = 46;
    memcpy((*frame).field.header.h_dest, dest, ETH_ALEN);
    memcpy((*frame).field.header.h_source, source, ETH_ALEN);
    (*frame).field.header.h_proto = htons(proto);
    memcpy((*frame).field.data, data, data_len);
    unsigned int frame_len = data_len + ETH_HLEN;
    for (int i = 0; i < 7; i++)
    {
        printf("%02x ", 0xaa);
    }
    printf("%02x ", 0xab); // 前导码和帧前定界符
    int k = 8;
    for (int i = 0; i < frame_len; i++, k++)
    {
        if (k % 8 == 0)
            printf(" ");
        if (k % 16 == 0)
            printf("\n");
        printf("%02x ", (*frame).buffer[i]);
    }

    unsigned char ch;
    unsigned char crc = 0x00;

    for (int i = 0; i < frame_len; i++)
    {
        ch = (*frame).buffer[i];
        for (int j = 0; j < 8; j++)
        {
            if (0x80 == (crc & (0x80)))
            {
                crc = (crc << 1) & (0xff);
                crc = crc | ((ch & 0x80) >> 7);
                crc = crc ^ (0x07);
            }
            else
            {
                crc = (crc << 1) & (0xff);
                crc = crc | ((ch & 0x80) >> 7);
            }
            ch = ch << 1;
        }
    }
    if (k % 8 == 0)
        printf(" ");
    if (k % 16 == 0)
        printf("\n");
    k++;
    printf("%02x ", 0x00);
    if (k % 8 == 0)
        printf(" ");
    if (k % 16 == 0)
        printf("\n");
    k++;
    printf("%02x ", crc);
    printf("\n");
    return frame_len;
}

int sendEth(union ethframe *frame, unsigned int frame_len, char *dest, int s, int ifindex)
{ // 发送以太网帧
    struct sockaddr_ll saddrll;
    memset(&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = ifindex;
    saddrll.sll_halen = ETH_ALEN;
    memcpy(saddrll.sll_addr, dest, ETH_ALEN);
    if (sendto(s, (*frame).buffer, frame_len, 0, (struct sockaddr *)&saddrll, sizeof(saddrll)) > 0)
    {
        // printf("Success!\n");
        return 1;
    }
    // printf("Error, could not send\n");
    return 0;
}

void mysend(char *data, short proto, char *source, char *dest, union ethframe *frame, unsigned int frame_len)
{ // 发送
    int s;
    struct ifreq ethreq;
    char *iface = "eth0"; // 网卡接口
    int ifindex;
    if ((s = socket(AF_PACKET, SOCK_RAW, htons(proto))) < 0)
    {
        printf("Error: could not open socket\n");
        return;
    }
    memset(&ethreq, 0x00, sizeof(ethreq));
    strncpy(ethreq.ifr_name, iface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFINDEX, &ethreq) < 0)
    {
        printf("Error: could not get interface index\n");
        close(s);
        return;
    }
    ifindex = ethreq.ifr_ifindex;
    if (sendEth(frame, frame_len, dest, s, ifindex) == 0)
        printf("Error, could not send\n");
    ;
    close(s);
}

void *mythreadA(void)
{                                  // 线程A
    int i = 0;                     // 发送成功次数
    int CollisionCounter = 0;      // 冲突计数器初始值为0
    double collisionWindow = 5.12; // 冲突窗口值取5.12ms
Loop:
    if (Bus == 0)
    {
        Bus = Bus | idA; // 模拟发送包
        usleep(12);
        if (Bus == idA) // 数据发送成功
        {
            mysend(dataA, protoA, sourceA, dest, &frameA, frame_lenA);
            i++;
            printf("主机A(线程号：%5ld): 发送成功 - 成功次数: %d 次\n\n", idA, i);
            Bus = 0;              // 内存清零
            CollisionCounter = 0; // 复原冲突计数器
            usleep(rand() % 10);  // 随机延时
            if (i < sendtimes)
                goto Loop;
        }
        else
        {
            CollisionCounter++;
            printf("主机A(线程号：%5ld): 发生第 %d 次冲突\n\n", idA, CollisionCounter);
            Bus = 0;
            if (CollisionCounter <= 16)
            {
                srand(time(0));
                int randNum = rand() % ((int)pow(2, (CollisionCounter > 10) ? 10 : CollisionCounter));
                unsigned long backofftime = (unsigned long)(collisionWindow * randNum);
                printf("主机A(线程号：%5ld): 启用退避算法  退避时间：%ld ms(randNum = %d)\n\n", idA, backofftime, randNum);
                usleep(backofftime);
                goto Loop;
            }
            else
            {
                printf("主机A(线程号：%5ld): 重发次数超过 16 次，发送失败\n\n", idA);
            }
        }
    }
    else
        goto Loop;
}

void *mythreadB(void)
{ // 线程B
    int i = 0;
    int CollisionCounter = 0;
    double collisionWindow = 5.12;
Loop:
    if (Bus == 0)
    {
        usleep(2);
        Bus = Bus | idB;
        usleep(3);
        if (Bus == idB)
        {
            mysend(dataB, protoB, sourceB, dest, &frameB, frame_lenB);
            i++;
            printf("主机B(线程号：%5ld): 发送成功 - 成功次数: %d 次\n\n", idB, i);
            Bus = 0;
            CollisionCounter = 0;
            usleep(rand() % 10);
            if (i < sendtimes)
                goto Loop;
        }
        else
        {
            CollisionCounter++;
            printf("主机B(线程号：%5ld): 发生第 %d 次冲突\n\n", idB, CollisionCounter);
            Bus = 0;
            if (CollisionCounter <= 16)
            {
                srand(time(0));
                int randNum = rand() % ((int)pow(2, (CollisionCounter > 10) ? 10 : CollisionCounter));
                unsigned long backofftime = (unsigned long)(collisionWindow * randNum);
                printf("主机B(线程号：%5ld): 启用退避算法  退避时间：%ld ms(randNum = %d)\n\n", idB, backofftime, randNum);
                usleep(backofftime);
                goto Loop;
            }
            else
            {
                printf("主机B(线程号：%5ld): 重发次数超过 16 次，发送失败\n\n", idB);
            }
        }
    }
    else
        goto Loop; // 总线忙
}

int main(void)
{
    printf("输入A需要发送的内容：");
    fgets(dataA, sizeof(dataA), stdin);
    dataA[strlen(dataA) - 1] = 0x00;
    printf("A的封装帧：\n");
    frame_lenA = encapEth(sourceA, dest, protoA, dataA, &frameA);
    printf("\n");

    printf("输入B需要发送的内容：");
    fgets(dataB, sizeof(dataB), stdin);
    dataB[strlen(dataB) - 1] = 0x00;
    printf("B的封装帧：\n");
    frame_lenB = encapEth(sourceB, dest, protoB, dataB, &frameB);
    printf("\n");

    printf("输入发送次数：");
    scanf("%d", &sendtimes);
    printf("\n");

    int ret = 0;
    // 创建双线程
    ret = pthread_create(&idA, NULL, (void *)mythreadA, NULL);
    if (ret)
    {
        printf("Create pthread error!\n");
        return 1;
    }
    ret = pthread_create(&idB, NULL, (void *)mythreadB, NULL);
    if (ret)
    {
        printf("Create pthread error!\n");
        return 1;
    }
    pthread_join(idA, NULL);
    pthread_join(idB, NULL);

    return 0;
}
