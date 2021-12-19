#pragma once
#include <string>
#include <Ws2tcpip.h>

typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
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


	struct Type {
		ushort qtype = 0;
		ushort qclass = 1;
	};

	struct ResourceRecord {
		Type qtc;
		uint ttl = 0;
		ushort dataLength = 0;
	};


	struct Query {
		std::string name;
		Type qtc;
	};

	struct Answer {
		Answer() = default;
		Answer(const char *name, ushort type = T_A, uint ttl = 0xff000000, void *rdata = nullptr, ushort dataLength = 4);
		std::string name;
		void *rdata = nullptr;
		size_t rdataLen = 0;
		ResourceRecord rr;
		Answer *next = nullptr;
	};

	struct Message {
		Header h;
		Query q;
		Answer *an = nullptr;
	};

	void getMessage(dns::Message *msg, void *buffer, size_t maxBuffSize = 1000);

	size_t createResponseBuffer(dns::Message &msg, void *buffer, size_t maxBuffSize);

}

namespace conf {

	struct Entry {
		const char *name = "";
		ulong A = 0;
	};

	void loadEntryTable();
	Entry *getEntry(unsigned long long index);
	Entry *findEntry(const char *name);
}

namespace util {
	const char *getDotName(char *buffer, size_t maxBuffSize, const char *netName);
}