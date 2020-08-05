#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct TcpHdr final {
	 u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    u_int th_seq;		/* sequence number */
    u_int th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
    u_char th_flags;
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
    u_int TH_OFF(){return (th_offx2 & 0xf0) >> 4;}
};
#pragma pack(pop)
