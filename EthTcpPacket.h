#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#pragma pack(push, 1)
struct EthTcpPacket {
	EthHdr eth_;
	IpHdr ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)