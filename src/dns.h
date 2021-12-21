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

#define DNS_SIZEOF_FLAGS 2
#define DNS_SIZEOF_HEADER 12
#define DNS_SIZEOF_TYPE 4
#define DNS_SIZEOF_RR 10

#define DNS_MAX_EXT_INDEX 0x3FFF
#define DNS_EXT_FLAG 0xc000

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
		ushort qtype = htons(T_A);
		ushort qclass = htons(1);
	};

	struct ResourceRecord {
		Type qtc;
		uint ttl = 0xff000000;
		ushort dataLength = 0;
	};


	struct Query {
		std::string name;
		Type qtc;
		ushort size() const;
	};

	struct Answer {
		friend struct Message;
		Answer() = default;
		Answer(const char *name, ushort type = T_A, uint ttl = 0xff000000, const void *rdata = nullptr, ushort dataLength = 0);
		std::string name;
		ResourceRecord rr;
		Answer *setRData(const void *ptr, ushort length);

		struct RData {
			void *data = nullptr;
			ushort len = 0;
		};
		const RData *getRData() const;

		Answer *extend(Answer *e);
		bool isExt() const;

		ushort size() const;
		ushort rdataIndex() const;

		const Answer *getNext() const;

	private:
		Answer *extPtr = nullptr;
		ushort startIndex = 0;
		ushort extIndex = 0;
		bool ext = false;

		RData rd;

		Answer *next = nullptr;
	};

	struct Message {
		Header h;
		Query q;
		Answer *getFirstAn() const, *getLastAn() const;
		Answer *addAnswer(), *addAnswer(const char *name, ushort type = T_A, uint ttl = 0xff000000, const void *rdata = nullptr, ushort dataLength = 0);
		~Message();
	private:
		Answer *an = nullptr, *lastAn = nullptr, *newAn(Answer *);
	};

	void getMessage(dns::Message *msg, void *buffer, size_t maxBuffSize = 1000);

	size_t createResponseBuffer(dns::Message &msg, void *buffer, size_t maxBuffSize);

}

namespace conf {

	struct Entry {
		char *name = nullptr;
		ulong A = 0;
		~Entry();
	};

	void loadEntryTable();
	bool getEntry(Entry *entr, unsigned long long index);
	bool findEntry(Entry *entr, const char *name);
}

namespace util {
	const char *getDotName(char *buffer, size_t maxBuffSize, const char *netName);
	const char *getReqType(char *buffer, size_t maxBuffSize, ushort type);
}