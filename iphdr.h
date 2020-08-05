#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    typedef enum {
		TCP = 0x06
	} Ptype;
    u_short ip_sum;		/* checksum */
    Ip ip_src;
    Ip ip_dst; /* source and dest address */
    u_int IP_HL(){return ip_vhl&0x0f;}
};
#pragma pack(pop)
