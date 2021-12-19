#pragma once

typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long long ullong;

//Type field of Query and Answer
#define T_A 1 /* host address */
#define T_NS 2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 /* mail routing information */

namespace dns {

	struct Flags {
		unsigned char rd : 1;     // recursion desired
		unsigned char tc : 1;     // truncated message
		unsigned char aa : 1;     // authoritive answer
		unsigned char opcode : 4; // purpose of message
		unsigned char qr : 1;     // query/response flag

		unsigned char rcode : 4;  // response code
		unsigned char z : 3;      // its z! reserved
		unsigned char ra : 1;     // recursion available
		Flags();
	};

	struct Header {
		ushort id = 0;
		Flags f;
		ushort qCount = 0;
		ushort anCount = 0;
		ushort authCount = 0;
		ushort addCount = 0;
	};


	struct Meta {
		ushort qtype = 0;
		ushort qclass = 1;
	};

	struct ResourceRecord {
		Meta qtc;
		uint ttl = 0;
		ushort dataLength = 0;
	};

	struct Query {
		char *name = nullptr;
		size_t len = 0;
		Meta qtc;
		~Query();
		Query(const Query &c) = delete;
		Query() = default;
	};

	struct Answer {
		char *name = nullptr;
		ResourceRecord rr;
		char *rdata = nullptr;
		~Answer();
		Answer(const Answer &c) = delete;
		Answer() = default;
	};

	struct Message {
		Header h;
		Query q;
		Answer *an = nullptr;
	};

	void getMessage(dns::Message *msg, void *buffer, size_t maxBuffLen = 1000);

	size_t createResponse(dns::Message &msg, void *buffer, size_t maxBuffLen);

	struct Entry {
		const char *name = "";
		ushort qtype = 0;
		uint ipv4 = T_A;
	};
}


