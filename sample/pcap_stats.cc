
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "bgh.h"

// Our sample session data
struct ssn_data_t {
    int count;
};

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN    6

struct eh_t {
    uint8_t src[ETHER_ADDR_LEN];
    uint8_t dst[ETHER_ADDR_LEN];
    uint16_t type;
};

struct iph_t {
        uint8_t  ip_vhl;
        uint8_t  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        uint8_t  ip_ttl;
        uint8_t  ip_p;
        u_short ip_sum;
        struct  in_addr ip_src;
        struct  in_addr ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct tcph_t {
        u_short th_sport;
        u_short th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        uint8_t  th_offx2;
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        uint8_t  th_flags;
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

void usage() {
//    printf("ssn_track sample\nUsing lib version %d.%d\n", ssn_track_VERSION_MAJOR, ssn_track_VERSION_MINOR);
    puts("Usage: ./pcap_stats <pcap>");
}

void pcap_cb(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
    bgh_t *tracker = (bgh_t*)args;

    iph_t *ip = (iph_t*)(packet + SIZE_ETHERNET);

    int size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("Skipping packet with invalid IP header length\n");
        return;
    }

    // Ignore if not TCP
    if(ip->ip_p != IPPROTO_TCP) 
        return;
    
    tcph_t *tcp = (tcph_t*)(packet + SIZE_ETHERNET + size_ip);

    int size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("Skipping packet with invalid TCP header length\n");
        return;
    }
    

    int payload_size = ntohs(ip->ip_len) - (size_ip + size_tcp);
    /*
    // uint8_t *payload = (uint8_t *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
    */

    bgh_key_t key;

    key.sip = ip->ip_src.s_addr;
    key.dip = ip->ip_dst.s_addr;
    key.sport = tcp->th_sport;
    key.dport = tcp->th_dport;
    key.vlan = 0;

    ssn_data_t *ssn = NULL;
    bgh_data_t *d = bgh_acquire(tracker, &key);

    if(!d) {
        // New session
        printf("New session: %s:%d -> %s:%d size %d\n", 
            inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), 
            inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport), payload_size);

        ssn = new ssn_data_t;
        ssn->count = 0;
        d = bgh_insert_acquire(tracker, &key, ssn);
        if(!d) {
            puts("Failed to save session");
            exit(-1);
        }
    }

    ssn = (ssn_data_t*)d->user;
    ssn->count++;
    bgh_release(tracker, d);
}

void free_data_cb(void *p) {
    ssn_data_t *ssn = (ssn_data_t*)p;
    printf("SSN completed. %d packets\n", ssn->count);
    delete ssn;
}

int main(int argc, char **argv) {
    if(argc < 2) {
        usage();
        return -1;
    }

    bgh_t *tracker = bgh_new(free_data_cb);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ph;

    if(!(ph = pcap_open_offline(argv[1], errbuf))) {
        printf("Failed to open pcap file: %s: %s\n", argv[1], errbuf);
        return -1;
    }
 
    pcap_loop(ph, 0, pcap_cb, (u_char*)tracker);

    bgh_free(tracker);

    pcap_close(ph);
}
