#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
//#include "./libnet/include/libnet/libnet-headers.h"


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_ip(u_int32_t ip);


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;

    }
    u_int8_t eth_header_size = 14;
    u_int8_t ipv4_header_size = 20;
    struct libnet_ethernet_hdr* eth_header;
    struct libnet_ipv4_hdr* ipv4_header;
    struct libnet_ipv4_hdr* check_header;
    struct libnet_tcp_hdr* tcp_header;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet = 0;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);

        //check if the packet is tcp_packet
        const u_char* check = packet;
        check = check+eth_header_size;
        check_header = (struct libnet_ipv4_hdr *)(check);
        if(check_header->ip_p != IPPROTO_TCP)
            continue;;

        //ethernet header
        eth_header = (struct libnet_ethernet_hdr *)(packet);
        packet = packet + eth_header_size;


        printf("src mac : ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
            printf("%x ", eth_header->ether_shost[i]);
        printf("\n");
        printf("dst mac : ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
            printf("%x ", eth_header->ether_dhost[i]);
        printf("\n");

        //ipv4 header
        ipv4_header = (struct libnet_ipv4_hdr *)(packet);
        packet = packet + ipv4_header_size;
        printf("src ip : ");
        print_ip(ntohl(ipv4_header->ip_src.s_addr));

        printf("dst ip : ");
        print_ip(ntohl(ipv4_header->ip_dst.s_addr));

        //tcp header
        tcp_header = (struct libnet_tcp_hdr *)(packet);

        u_int16_t tcp_offset = tcp_header->th_off;
        u_int8_t tcp_header_size =(ntohs(tcp_offset)>>4)/4;
        packet = packet + tcp_header_size;

        printf("src port : ");
        printf("%d\n", ntohs(tcp_header->th_sport));
        printf("dst port :");
        printf("%d\n",ntohs(tcp_header->th_dport));

        //check payload
        u_int8_t remained_payload = header->caplen - tcp_header_size-eth_header_size- ipv4_header_size;

        if(remained_payload>0)
        {
            printf("Payload hexadecimal value(8bytes) :");
            printf("%8x ",ntohl(*(uint32_t*)(packet)));
            printf("%8x\n",ntohl(*(uint32_t*)(packet+4)));

        }
        else
        {
            printf("not exist payload\n");
        }
        printf("\n");
    }

    pcap_close(pcap);
}

void print_ip(u_int32_t ip)
{
    printf("%d. %d. %d .%d\n", (ip&0xff000000)>>24,(ip&0xff0000)>>16,(ip&0xff00)>>8,(ip&0xff));
}

