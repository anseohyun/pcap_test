#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

#define MAX_IP_LEN 16

int main(int argc, char *argv[]) {
	
	pcap_t *pcap;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct in_addr ip_src, ip_dst;
	int sent_packets_num = 0;
	int received_packets_num = 0;
	int sent_bytes = 0;
	int received_bytes = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap = pcap_open_offline(argv[1], errbuf);
		  
	while((packet = pcap_next(pcap, &header)) != NULL){
		struct ip *ip_hdr = (struct ip*)(packet + 14);

		ip_src.s_addr = ip_hdr->ip_src.s_addr;
		ip_dst.s_addr = ip_hdr->ip_dst.s_addr;		

		if(strcmp(inet_ntoa(ip_src), "0.0.0.0") != 0){
			sent_packets_num++;
			sent_bytes += header.len;
		}
		else{
			received_packets_num++;
			received_bytes += header.len;
		}
	}

	printf("송신 패킷 수 : %d\n", sent_packets_num);
        printf("수신 패킷 수 : %d\n", received_packets_num);
	printf("송신 패킷 바이트 : %d\n", sent_bytes);
        printf("수신 패킷 바이트 : %d\n", received_bytes);

	pcap_close(pcap);

	return 0;
}
