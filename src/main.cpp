#include <cstring>
#include "dns.h"
#include "incl.h"

dns::Flags::Flags() {
	memset(this, 0, sizeof(Flags));
}

dns::Query::~Query() { if(name) delete[]name; }
dns::Answer::~Answer() { if(name) delete[]name; if(rdata) delete[]rdata; }

void dns::getMessage(dns::Message *msg, void *buffer, size_t maxBuffLen) {

	char *currBuff = (char *)buffer;

	// header

	memcpy(&msg->h, currBuff, sizeof(Header));
	currBuff += sizeof(Header);


	// query

	msg->q.len = strlen(currBuff) + 1;
	msg->q.name = new char[msg->q.len];
	strcpy_s(msg->q.name, msg->q.len, currBuff);
	currBuff += msg->q.len;

	memcpy(&msg->q.qtc, currBuff, 2 * sizeof(ushort));
	currBuff += 2 * sizeof(msg->q.qtc);

}

size_t dns::createResponse(dns::Message &msg, void *buffer, size_t maxBuffLen) {
	char *currBuff = (char *)buffer;
	size_t retSize = 0;

	// header

	memcpy(currBuff, reinterpret_cast<void*>(&msg.h), sizeof(Header));
	currBuff += sizeof(Header);
	retSize += sizeof(Header);


	// query

	strcpy_s(currBuff, msg.q.len, msg.q.name);
	currBuff += msg.q.len;
	retSize += msg.q.len;

	memcpy(currBuff, reinterpret_cast<void *>(&msg.q.qtc), sizeof(int));
	currBuff += sizeof(msg.q.qtc);
	retSize += sizeof(msg.q.qtc);


	// answer

	strcpy_s(currBuff, msg.q.len, msg.q.name);
	currBuff += msg.q.len;
	retSize += msg.q.len;

	memcpy(currBuff, reinterpret_cast<void *>(&msg.an->rr), 10);
	currBuff += 10;
	retSize += 10;

	short dataLen = ntohs(msg.an->rr.dataLength);
	memcpy(currBuff, msg.an->rdata, dataLen);
	currBuff += dataLen;
	retSize += dataLen;

	return retSize;

}
