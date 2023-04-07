#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

int is_valid_arp(arp_pkt_t *pkt)
{
    return (pkt->hw_type16 == swap16(ARP_HW_ETHER) && pkt->hw_len == NET_MAC_LEN && pkt->pro_len == NET_IP_LEN && pkt->pro_type16 == swap16(NET_PROTOCOL_IP) && (pkt->opcode16 == swap16(ARP_REQUEST) || pkt->opcode16 == swap16(ARP_REPLY)));
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));

    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;

    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    pkt->opcode16 = swap16(ARP_REQUEST);

    buf_add_padding(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT - sizeof(arp_pkt_t));

    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));

    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;

    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    pkt->opcode16 = swap16(ARP_REPLY);

    buf_add_padding(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT - sizeof(arp_pkt_t));

    ethernet_out(&txbuf, (uint8_t *)map_get(&arp_table, target_ip), NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < sizeof(arp_pkt_t))
    {
        return;
    }

    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;
    buf_remove_header(buf, sizeof(arp_pkt_t));

    if (!is_valid_arp(pkt))
    {
        return;
    }

    uint8_t *target_ip = pkt->sender_ip;
    map_set(&arp_table, target_ip, src_mac);

    buf_t *cache = (buf_t *)map_get(&arp_buf, target_ip);
    if (cache != NULL)
    {
        ethernet_out(cache, src_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, target_ip);
    }
    else if (pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN) == 0)
    {
        arp_resp(target_ip, pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);
    if (mac != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }
    if (map_get(&arp_buf, ip) == NULL)
    {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}