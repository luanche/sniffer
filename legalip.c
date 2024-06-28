#include <stdio.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int checkip(const char *ip)
{
    int i = 0;
    int count[2] = {0};
    const char *s = ".";
    char TempIP[16];
    memset(TempIP, 0, sizeof(TempIP));
    int IPAddr[4] = {0};
    int pos[3] = {0};

    memcpy(TempIP, ip, sizeof(TempIP));
    for (i = 0; i < strlen(TempIP); i++)
    {
        if (TempIP[0] != '.' && TempIP[i] == '.' && TempIP[i + 1] != '\0' && TempIP[i + 1] != '.')
        {
            count[0]++;
        }
        if (!isdigit(TempIP[i]))
        {
            count[1]++;
        }
    }

    if (count[0] != 3 || count[1] != 3)
    {
        return -1;
    }

    IPAddr[0] = atoi(strtok(TempIP, s));
    IPAddr[1] = atoi(strtok(NULL, s));
    IPAddr[2] = atoi(strtok(NULL, s));
    IPAddr[3] = atoi(strtok(NULL, s));

    if ((IPAddr[0] >= 0 && IPAddr[0] <= 255) && (IPAddr[1] >= 0 && IPAddr[1] <= 255) && (IPAddr[2] >= 0 && IPAddr[2] <= 255) && (IPAddr[3] >= 0 && IPAddr[3] <= 255))
    {
        return 0;
    }
    else
    {
        return -1;
    }
}
int checkabcde(in_addr_t ipnum)
{
    int ip1, ip2;
    ip1 = ipnum % 0x100;
    ip2 = ipnum / 0x100 % 0x100;
    if (ip1 >= 1 && ip1 <= 127)
    {
        printf("A类地址");
        if (ip1 == 10)
            printf("/私有地址");
        if (ip1 == 127)
            printf("/回环地址");
    }
    else if (ip1 >= 128 && ip1 <= 191)
    {
        printf("B类地址");
        if (ip1 == 172 && ip2 >= 16 && ip2 <= 31)
            printf("/私有地址");
    }
    else if (ip1 >= 192 && ip1 <= 223)
    {
        printf("C类地址");
        if (ip1 == 192 && ip2 == 168)
            printf("/私有地址");
    }
    else if (ip1 >= 224 && ip1 <= 239)
    {
        printf("D类地址");
    }
    else
    {
        printf("E类地址");
    }
}

int main()
{
    char ip[100] = {""};
    printf("输入点分割十进制IP地址(输入 # 结束):");
    scanf("%s", ip);
    while (strcmp(ip, "#") != 0)
    {
        printf("%s->", ip);
        if (-1 == checkip(ip) || 0x0 == inet_addr(ip) || 0xffffffff == inet_addr(ip) || inet_addr(ip) % 0x100 == 0)
        {
            printf("no");
        }
        else
        {
            printf("%0x->", inet_addr(ip));
            printf("yes->");
            checkabcde(inet_addr(ip));
        }
        printf("\n");
        printf("输入点分割十进制IP地址(输入 # 结束):");
        scanf("%s", ip);
    }

    return 0;
}
