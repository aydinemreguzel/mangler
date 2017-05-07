#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
/*#include <netinet/tcp.h>*/
/*#include <netinet/udp.h>*/

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "include/common.h"
#include "include/plugin.h"

#define BUFSIZE 4096

typedef struct {
    struct iphdr ip;
    struct tcphdr tcp;
} __attribute__((packed)) ip4_tcp_t;

typedef struct {
    struct iphdr ip;
    struct udphdr udp;
    char dat[];
} __attribute__((packed)) ip4_udp_t;

typedef struct {
    struct iphdr ip;
    char dat[];
} __attribute__((packed)) ipv4_t;

/* sudo iptables -t mangle -I PREROUTING -i eth1 -s 192.168.1.200 -p udp -j NFQUEUE --queue-num=0 */

extern plugin_t* mangle_plugins[];

static plugin_t* get_plugin(const char* name)
{
    int idx = 0;

    while (mangle_plugins[idx] != NULL) {
        plugin_t* cur = mangle_plugins[idx];
        if (!strcmp(name, cur->name)) {
            return cur;
        }
        idx++;
    }

    return NULL;
}

static void list_plugins()
{
    int idx = 0;

    printf("Available plugins:\n");

    while (mangle_plugins[idx] != NULL) {
        plugin_t* cur = mangle_plugins[idx];
        printf("%20s\t->\tudp: %d tcp: %d ip4:%d \n", cur->name,
            !!(cur->type & PLUGIN_UDP),
            !!(cur->type & PLUGIN_TCP),
            !!(cur->type & PLUGIN_IPV4)
            );
        idx++;
    }
}

/*******************************************/
/* Imported from libnetfilter queue soruce */
/*******************************************/
static uint16_t checksum(uint32_t sum, uint16_t* buf, int size)
{
    while (size > 1) {
        sum += *buf++;
        size -= sizeof(uint16_t);
    }
    if (size)
        sum += *(uint8_t*)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

/* fixed the implementation from libnetfilter_queue */
static uint16_t checksum_udp_ipv4(struct iphdr* iph)
{
    uint32_t sum = 0;
    uint32_t iph_len = iph->ihl * 4;
    uint32_t len = ntohs(iph->tot_len) - iph_len;
    uint8_t* payload = (uint8_t*)iph + iph_len;

    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += htons(len);

    return checksum(sum, (uint16_t*)payload, len);
}
/*******************************************/

static int udp_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
    struct nfq_data* nfa, void* data)
{
    int rc;
    int id = 0;
    int ret = 0;
    uint16_t dat_len;
    unsigned char* buffer;
    struct nfqnl_msg_packet_hdr* ph;
    ip4_udp_t* ip;
    plugin_t* plugin = (plugin_t*)data;

    if (!plugin) {
        ret = -1;
        goto out;
    }

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        ret = -1;
        goto out;
    }

    id = ntohl(ph->packet_id);
    rc = nfq_get_payload(nfa, &buffer);

    ip = (ip4_udp_t*)buffer;

    PRINT("src addr: " IP_FMT "\n", IPADDR(ip->ip.saddr));
    PRINT("dest addr: " IP_FMT "\n", IPADDR(ip->ip.daddr));
    PRINT("dest port: %d\n", ntohs(ip->udp.dest));
    PRINT("len: %d\n", ntohs(ip->udp.len));

    dat_len = ntohs(ip->udp.len) - sizeof(struct udphdr);

    plugin->callback(plugin, ip->dat, &dat_len);

    /* update len */
    ip->udp.len = htons(dat_len + sizeof(struct udphdr));
    ip->ip.tot_len = htons(dat_len + sizeof(struct udphdr) + sizeof(struct iphdr));

    /* update checksums */
    nfq_ip_set_checksum(&ip->ip);
    ip->udp.check = 0;
    ip->udp.check = checksum_udp_ipv4(&ip->ip);

    /* done with the packet */
    rc = nfq_set_verdict(qh, id, NF_ACCEPT, htons(ip->ip.tot_len), buffer);
    if (rc < 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int tcp_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
    struct nfq_data* nfa, void* data)
{
    int rc;
    int id = 0;
    int ret = 0;
    uint16_t dat_len;
    unsigned char* buffer;
    struct nfqnl_msg_packet_hdr* ph;
    ip4_tcp_t* ip;
    plugin_t* plugin = (plugin_t*)data;
    char* payload;

    if (!plugin) {
        ret = -1;
        goto out;
    }

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        ret = -1;
        goto out;
    }

    id = ntohl(ph->packet_id);
    rc = nfq_get_payload(nfa, &buffer);

    ip = (ip4_tcp_t*)buffer;

    PRINT("src addr: " IP_FMT "\n", IPADDR(ip->ip.saddr));
    PRINT("dest addr: " IP_FMT "\n", IPADDR(ip->ip.daddr));
    PRINT("dest port: %d\n", ntohs(ip->tcp.dest));

    payload = buffer + sizeof(struct iphdr) + (ip->tcp.doff * 4);
    dat_len = ntohs(ip->ip.tot_len) - (sizeof(struct iphdr) + (ip->tcp.doff * 4));

    /* only call callback if there's data */
    if (dat_len > 0) {
        plugin->callback(plugin, payload, &dat_len);
    }

    /* update len */
    ip->ip.tot_len = htons(sizeof(struct iphdr) + (ip->tcp.doff * 4) + dat_len);

    /* update checksums */
    nfq_ip_set_checksum(&ip->ip);

    nfq_tcp_compute_checksum_ipv4(&ip->tcp, &ip->ip);

    /* done with the packet */
    rc = nfq_set_verdict(qh, id, NF_ACCEPT, htons(ip->ip.tot_len), buffer);
    if (rc < 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int ipv4_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
    struct nfq_data* nfa, void* data)
{
    int rc;
    int id = 0;
    int ret = 0;
    uint16_t dat_len;
    unsigned char* buffer;
    struct nfqnl_msg_packet_hdr* ph;
    ipv4_t* ip;
    plugin_t* plugin = (plugin_t*)data;

    if (!plugin) {
        ret = -1;
        goto out;
    }

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        ret = -1;
        goto out;
    }

    id = ntohl(ph->packet_id);
    rc = nfq_get_payload(nfa, &buffer);

    ip = (ipv4_t*)buffer;

    PRINT("src addr: " IP_FMT "\n", IPADDR(ip->ip.saddr));
    PRINT("dest addr: " IP_FMT "\n", IPADDR(ip->ip.daddr));
    PRINT("len: %d\n", ntohs(ip->ip.tot_len));

    dat_len = ntohs(ip->ip.tot_len) - sizeof(struct iphdr);

    plugin->callback(plugin, ip->dat, &dat_len);

    /* update len */
    ip->ip.tot_len = htons(dat_len + sizeof(struct iphdr));

    /* update checksums */
    nfq_ip_set_checksum(&ip->ip);

    /* done with the packet */
    rc = nfq_set_verdict(qh, id, NF_ACCEPT, htons(ip->ip.tot_len), buffer);
    if (rc < 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int init_queue(plugin_t* plugin, plug_type_e plug_type)
{
    int ret = 0;
    int rc;
    int fd;
    struct nfq_handle* h = NULL;
    struct nfq_q_handle* qh;
    struct nfnl_handle* nh;
    char buf[BUFSIZE];
    ssize_t read_len;
    nfq_callback* nf_cb = NULL;

    h = nfq_open();
    if (!h) {
        PRINT_ERR("cannot open\n");
        ret = -1;
        goto out;
    }

    nfq_unbind_pf(h, AF_INET);

    rc = nfq_bind_pf(h, AF_INET);
    if (rc < 0) {
        PRINT_ERR("cannot bind\n");
        ret = -1;
        goto out;
    }

    switch (plug_type) {
        case PLUGIN_UDP:
            nf_cb = udp_callback;
            break;
        case PLUGIN_TCP:
            nf_cb = tcp_callback;
            break;
        case PLUGIN_IPV4:
            nf_cb = ipv4_callback;
            break;
        default:
            PRINT_ERR("unknown cb type\n");
            ret = -1;
            goto out;
    }

    qh = nfq_create_queue(h, 0, nf_cb, (void*)plugin);
    if (!qh) {
        PRINT_ERR("cannot create queue\n");
        ret = -1;
        goto out;
    }

    rc = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    if (ret < 0) {
        PRINT_ERR("cannot set mode\n");
        ret = -1;
        goto out;
    }

    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    for (;;) {
        read_len = recv(fd, buf, BUFSIZE, 0);
        if (read_len < 0) {
            ret = -1;
            goto out;
        }

        nfq_handle_packet(h, buf, read_len);
    }

out:
    if (h != NULL) {
        nfq_close(h);
    }

    return ret;
}

static void usage()
{
    printf("\n");
    printf("USAGE:\n");
    printf("    mangler [protocol (udp/tcp/ip4)] [plugin] [plugin_arguments]\n");
    printf("\n");

    list_plugins();
}

static plug_type_e get_type(const char* str)
{
    if (!strcmp(str, "udp")) {
        return PLUGIN_UDP;
    } else if (!strcmp(str, "tcp")) {
        return PLUGIN_TCP;
    } else if (!strcmp(str, "ipv4")) {
        return PLUGIN_IPV4;
    } else {
        return PLUGIN_UNKNOWN;
    }
}

int main(int argc, char* argv[])
{
    int ret = 0;
    plug_type_e plug_type = PLUGIN_UNKNOWN;
    plugin_t* plug = NULL;

    if (argc < 3) {
        PRINT_ERR("Not enough arguments\n");
        ret = 1;
        usage();
        goto out;
    }

    plug_type = get_type(argv[1]);
    if (plug_type == PLUGIN_UNKNOWN) {
        PRINT_ERR("No such type\n");
        ret = 1;
        goto out;
    }

    plug = get_plugin(argv[2]);
    if (!plug) {
        PRINT_ERR("No such plugin\n");
        ret = 1;
        goto out;
    }

    if (!(plug->type & plug_type)) {
        PRINT_ERR("Protocol unsupported by plugin\n");
        ret = 1;
        goto out;
    }

    ret = plug->init(plug, argc - 2, &argv[2]);
    if (ret != 0) {
        PRINT_ERR("can't init plugin\n");
        ret = 1;
        goto out;
    }

    ret = init_queue(plug, plug_type);
    if (ret != 0) {
        PRINT_ERR("exited with error\n");
        ret = 1;
        goto out;
    }

    plug->destroy(plug);
out:
    return ret;
}
