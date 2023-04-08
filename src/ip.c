#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

#define MIN_IP_HDR_LEN_UNIT 5
#define TTL 64
#define MAX_PAYLOAD_LEN 1480

int frag_id = 0;

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }

    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    if (!(hdr->version == IP_VERSION_4 && swap16(hdr->total_len16) <= buf->len && memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) == 0))
    {
        return;
    }

    uint16_t checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t cal_checksum = checksum16((uint16_t *)hdr, hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    if (checksum != (cal_checksum))
    {
        return;
    }
    hdr->hdr_checksum16 = checksum;

    buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));

    if (hdr->protocol == NET_PROTOCOL_UDP || hdr->protocol == NET_PROTOCOL_ICMP)
    {
        buf_remove_header(buf, hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
        net_in(buf, hdr->protocol, hdr->src_ip);
    }
    else
    {
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    buf_add_header(buf, MIN_IP_HDR_LEN_UNIT * IP_HDR_LEN_PER_BYTE);
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    hdr->version = IP_VERSION_4;
    hdr->hdr_len = MIN_IP_HDR_LEN_UNIT;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16(offset | mf);
    hdr->ttl = TTL;
    hdr->protocol = protocol;
    hdr->hdr_checksum16 = 0;
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    uint16_t checksum = checksum16((uint16_t *)hdr, hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    hdr->hdr_checksum16 = checksum;

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    int sent = 0;
    while (buf->len > MAX_PAYLOAD_LEN)
    {
        buf_t ip_buf;
        buf_init(&ip_buf, MAX_PAYLOAD_LEN);
        memcpy(ip_buf.data, buf->data, MAX_PAYLOAD_LEN);
        buf_remove_header(buf, MAX_PAYLOAD_LEN);
        ip_fragment_out(&ip_buf, ip, protocol, frag_id, sent >> 3, IP_MORE_FRAGMENT);

        sent += MAX_PAYLOAD_LEN;
    }
    buf_t last_ip_buf;
    buf_init(&last_ip_buf, buf->len);
    memcpy(last_ip_buf.data, buf->data, buf->len);
    ip_fragment_out(&last_ip_buf, ip, protocol, frag_id, sent >> 3, 0);
    frag_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}