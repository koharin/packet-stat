#include <iostream>
#include <cstring>
#include <pcap.h>
#include <stdint.h>
#define SIZE_ETHERNET 14
#include <net/ethernet.h> //ether_header
#include <functional>
#include <string>

using namespace std;

struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src; //source address
        struct in_addr ip_dst; //dest address 
        u_char ip_hdr_len:4;
        u_char ip_ver:4;
};

class Hasher
{
public:
  size_t operator() (const struct in_addr key) const
  {
      return hash<u_int64_t>()(key.s_addr);
  }
};
class EqualFn
{
public:
  bool operator() (const struct in_addr &t1, const struct in_addr &t2) const
  {
      return t1.s_addr == t2.s_addr;
  }
};

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
};

struct sniff_udp {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct data {
    uint32_t Tx_Packets;
    uint32_t Tx_Bytes;
    uint32_t Rx_Packets;
    uint32_t Rx_Bytes;
};
