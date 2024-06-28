# Sniffer

Simple network sniffer with protocol/source ip/destination ip filters.

## Build

```bash
gcc -g sniffer.c -o sniffer
```

## Usage

```bash
./sniffer -h
usage: sniffer [-p 协议] [-s 源IP地址] [-d 目标IP地址]
    -p    协议[tcp/udp/icmp/igmp/arp]
    -s    源IP地址 address
    -d    目标IP地址 address
```

## Example

```bash
./sniffer -p icmp -s 172.21.164.14

---- 第1个:74字节 ----
Ethernet:
  源MAC地址: 00:15:5d:f3:7a:68 , 目的MAC地址: 00:15:5d:8a:d5:fb
  类型: 0x0800
IPv4:
  源IP: 172.21.164.14 , 目的IP: 172.21.160.1
  TTL: 64 , 首部长度: 20Byte
ICMP:
  类型: 0 (Echo (ping) 响应) , 代码: 0


---- 第2个:74字节 ----
Ethernet:
  源MAC地址: 00:15:5d:f3:7a:68 , 目的MAC地址: 00:15:5d:8a:d5:fb
  类型: 0x0800
IPv4:
  源IP: 172.21.164.14 , 目的IP: 172.21.160.1
  TTL: 64 , 首部长度: 20Byte
ICMP:
  类型: 0 (Echo (ping) 响应) , 代码: 0

```

# SYN-Flood

## Build

```bash
gcc -g synflood.c -o synflood
```

## Usage

```bash
# usage: ./synflood source-ip port
./synflood 172.21.160.1 8888
```
