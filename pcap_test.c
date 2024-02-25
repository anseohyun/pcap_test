#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_IP_LEN 16

int main(int argc, char *argv[]) {
    
    pcap_t *pcap;
    const u_char *packet;
    struct pcap_pkthdr header;
    int sent_bytes = 0;
    int received_bytes = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct {
        int sent_packets_num;
        int received_packets_num;
        int sent_bytes;
        int received_bytes;
    } packet_stat[MAX_IP_LEN];

    // packet_stat 배열 초기화
    for (int i = 0; i < MAX_IP_LEN; ++i) {
        packet_stat[i].sent_packets_num = 0;
        packet_stat[i].received_packets_num = 0;
        packet_stat[i].sent_bytes = 0;
        packet_stat[i].received_bytes = 0;
    }
    
    // pcap 파일을 오픈, pcap 구조체에 연결
    pcap = pcap_open_offline(argv[1], errbuf);
    
    // pcap_next, pcap 핸들에서 다음 패킷을 읽어오는 함수      
    while((packet = pcap_next(pcap, &header)) != NULL){
        struct ip *ip_hdr = (struct ip*)(packet + 14);

        char ip_src_str[MAX_IP_LEN];
        char ip_dst_str[MAX_IP_LEN];
        // inet_ntop 함수에서 AF_INET을 사용하면 함수가 IPv4 주소를 텍스트 형식으로 변환
        inet_ntop(AF_INET, &ip_hdr->ip_src, ip_src_str, sizeof(ip_src_str));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, ip_dst_str, sizeof(ip_dst_str));

        int ip_src_index = atoi(strtok(ip_src_str, "."));
        int ip_dst_index = atoi(strtok(ip_dst_str, "."));

        if(ip_src_index > 0 && ip_src_index < MAX_IP_LEN){
            packet_stat[ip_src_index].sent_packets_num++;
            packet_stat[ip_src_index].sent_bytes += header.len;
        }

        if(ip_dst_index > 0 && ip_dst_index < MAX_IP_LEN){
            packet_stat[ip_dst_index].received_packets_num++;
            packet_stat[ip_dst_index].received_bytes += header.len;
        }
    }

    printf("IP 주소별 송신 및 수신 패킷 정보:\n");
    for (int i = 0; i < MAX_IP_LEN; ++i) {
        printf("IP 주소 %d.%d.%d.%d:\n", i, 0, 0, 0);
        printf("송신 패킷 수: %d\n", packet_stat[i].sent_packets_num);
        printf("수신 패킷 수: %d\n", packet_stat[i].received_packets_num);
        printf("송신 패킷 바이트: %d\n", packet_stat[i].sent_bytes);
        printf("수신 패킷 바이트: %d\n", packet_stat[i].received_bytes);
        printf("\n");
    }

    pcap_close(pcap);

    return 0;
}

