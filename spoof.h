#pragma once

#include <cstdint>
#include <cstring>
#include "ip.h"
#include "mac.h"
#include "EthArpPacket.h"
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