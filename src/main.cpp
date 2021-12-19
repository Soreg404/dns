#include "dns.h"
#include "incl.h"

dns::Flags::Flags() {
	memset(this, 0, sizeof(Flags));
}

dns::Answer::Answer(const char *name, ushort type, uint ttl, void *rdata, ushort dataLength): name(name), rdata(rdata), rdataLen(dataLength) {
	rr.qtc.qclass = htons(1);
	rr.qtc.qtype = htons(type);
	rr.dataLength = htons(dataLength);
}

void dns::getMessage(dns::Message *msg, void *buffer, size_t maxBuffSize) {

	char *currBuff = (char *)buffer;

	// header

	memcpy(&msg->h, currBuff, sizeof(Header));
	currBuff += sizeof(Header);


	// query

	msg->q.name = currBuff;
	currBuff += msg->q.name.length() + 1;

	memcpy(&msg->q.qtc, currBuff, 2 * sizeof(ushort));
	currBuff += 2 * sizeof(msg->q.qtc);

}

size_t dns::createResponseBuffer(dns::Message &msg, void *buffer, size_t maxBuffSize) {

	char *currBuff = (char *)buffer;
	size_t buffSize = 0;

#define BUFOFFS (currBuff + buffSize)

	// header

	memcpy(BUFOFFS, reinterpret_cast<void*>(&msg.h), sizeof(Header));
	buffSize += sizeof(Header);


	// query

	strcpy_s(BUFOFFS, msg.q.name.length() + 1, msg.q.name.c_str());
	buffSize += msg.q.name.length() + 1;

	memcpy(BUFOFFS, reinterpret_cast<void *>(&msg.q.qtc), sizeof(int));
	buffSize += sizeof(msg.q.qtc);


	// answer

	strcpy_s(BUFOFFS, msg.an->name.length() + 1, msg.an->name.c_str());
	buffSize += msg.an->name.length() + 1;

	memcpy(BUFOFFS, reinterpret_cast<void *>(&msg.an->rr), 10);
	buffSize += 10;

	short dataLen = ntohs(msg.an->rr.dataLength);
	memcpy(BUFOFFS, msg.an->rdata, dataLen);
	buffSize += dataLen;

	return buffSize;

}


const char *util::getDotName(char *buffer, size_t maxBuffSize, const char *netName) {
	size_t netNameLen = strlen(netName);
	if(netNameLen >= maxBuffSize) return "";
	strcpy_s(buffer, netNameLen + 1, netName);
	for(int i = 0; i < netNameLen; i++) if(buffer[i] < 32) buffer[i] = '.';
	return buffer;
}