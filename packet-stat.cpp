#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include "header.h"
#include <netinet/in.h>
#include <unordered_map>

using namespace std;

int main(int argc, char* argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE]; //Error string
    pcap_t *pcap_handle;
    
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const struct sniff_ethernet *ethernet; //ethernet header
    const struct sniff_udp *udp;
    
    unordered_map<struct in_addr, struct data, Hasher, EqualFn> Endpoints_IPv4; //key: ip addr, values: data

    if(argc < 2){
        cout << "Usage: ./packet-stat <pcap file>" << endl;
        exit(1);
    }

    if(!(pcap_handle = pcap_open_offline(argv[1], errbuf))){
        cout << "Error: " << errbuf << endl;
        exit(1);
    }

    cout << argv[1] << " file loaded" << endl;
    
    while((res = pcap_next_ex(pcap_handle, &header, &packet)) >= 0){    
        if(res == 0)
            continue;
        if(res == -1 || res == -2) break;
    
        ethernet = (struct sniff_ethernet*)(packet);
        
        if(ntohs(ethernet->ether_type == ETHERTYPE_IP)){
            
            ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
            
            if(Endpoints_IPv4.find(ip->ip_src) == Endpoints_IPv4.end()){
                Endpoints_IPv4.at(ip->ip_src).Tx_Packets = 0;
                Endpoints_IPv4.at(ip->ip_src).Tx_Bytes = 0;
                Endpoints_IPv4.at(ip->ip_src).Rx_Packets = 0;
                Endpoints_IPv4.at(ip->ip_src).Rx_Bytes = 0;
            }
            else{
                Endpoints_IPv4.at(ip->ip_src).Tx_Packets++;
                Endpoints_IPv4.at(ip->ip_src).Tx_Bytes += header->caplen;
            }
            if(Endpoints_IPv4.find(ip->ip_dst) == Endpoints_IPv4.end()){
                Endpoints_IPv4.at(ip->ip_dst).Rx_Packets = 0;
                Endpoints_IPv4.at(ip->ip_dst).Rx_Bytes = 0;
                Endpoints_IPv4.at(ip->ip_dst).Tx_Packets = 0;
                Endpoints_IPv4.at(ip->ip_dst).Tx_Bytes = 0;
            }
            else{
                Endpoints_IPv4.at(ip->ip_dst).Rx_Packets++;
                Endpoints_IPv4.at(ip->ip_dst).Rx_Bytes += header->caplen;
            }
        }
    }
    //unordered_map<struct in_addr, struct data>::iterator iter; 
    for(auto iter=Endpoints_IPv4.begin(); iter != Endpoints_IPv4.end(); iter++)
    {
        printf("Address: %s ", inet_ntoa(iter->first));
        printf("Packets: %d", (iter->second).Tx_Packets + (iter->second).Rx_Packets);
        printf("Bytes: %u", (iter->second).Rx_Bytes + (iter->second).Rx_Bytes);
        printf("Tx Packets: %d", (iter->second).Tx_Packets);
        printf("Tx Bytes: %u", (iter->second).Tx_Bytes);
        printf("Rx Packets: %d", (iter->second).Rx_Packets);
        printf("Rx Bytes: %u", (iter->second).Rx_Bytes);
        cout << "-----------------------------------------------------" << endl;
    }
    pcap_close(pcap_handle);
    
    return 0;
}
