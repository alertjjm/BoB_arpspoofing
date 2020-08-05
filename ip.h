#pragma once

#include <cstdint>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
struct Ip final {
	static const int SIZE = 4;

	//
	// constructor
	//
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);
	Ip(const struct in_addr ntwk_bytodr_ip);
	//
	// casting operator
	//
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	//
	// comparison operator
	//
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

protected:
	uint32_t ip_;
};
