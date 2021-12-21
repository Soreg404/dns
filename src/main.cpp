#include "dns.h"
#include "incl.h"

dns::Flags::Flags() {
	memset(this, 0, sizeof(Flags));
}

ushort dns::Query::size() const {
	return name.length() + 1 + DNS_SIZEOF_TYPE;
}

dns::Answer::Answer(const char *name, ushort type, uint ttl, const void *rdata, ushort dataLength): name(name) {
	rr.qtc.qclass = htons(1);
	rr.qtc.qtype = htons(type);

	setRData(rdata, dataLength);
}

dns::Answer *dns::Answer::setRData(const void *ptr, ushort length) {
	if(rd.data) delete[]rd.data;
	if(ptr) {
		rd.len = length;
		rr.dataLength = htons(length);
		rd.data = new char[length];
		memcpy(rd.data, ptr, length);
	} else {
		rd.data = nullptr;
		rd.len = 0;
		rr.dataLength = 0;
	}
	return this;
}
const dns::Answer::RData *dns::Answer::getRData() const {
	return &rd;
}

dns::Answer *dns::Answer::extend(Answer *e) {
	ext = true;
	if(e) extIndex = htons(DNS_EXT_FLAG + (e->startIndex + e->rdataIndex()));
	else extIndex = htons(DNS_EXT_FLAG + DNS_SIZEOF_HEADER);
	extPtr = e;
	name = std::string(reinterpret_cast<const char *>(&extIndex), 2);
	return this;
}

bool dns::Answer::isExt() const {
	return ext;
}

ushort dns::Answer::size() const {
	return (ext ? 2 : name.length() + 1) + DNS_SIZEOF_RR + rd.len;
}

ushort dns::Answer::rdataIndex() const {
	return (ext ? 2 : name.length() + 1) + DNS_SIZEOF_RR;
}

const dns::Answer *dns::Answer::getNext() const { return next; }

dns::Answer *dns::Message::getFirstAn() const { return an; }
dns::Answer *dns::Message::getLastAn() const { return lastAn; }

dns::Answer *dns::Message::newAn(dns::Answer *na) {
	if(!lastAn) {
		na->startIndex = DNS_SIZEOF_HEADER + q.size();
		return lastAn = an = na;
	}
	else na->startIndex = lastAn->startIndex + lastAn->size();
	return lastAn = lastAn->next = na;
}
dns::Answer *dns::Message::addAnswer() {
	return newAn(new Answer);
}
dns::Answer *dns::Message::addAnswer(const char *name, ushort type, uint ttl, const void *rdata, ushort dataLength) {
	return newAn(new Answer(name, type, ttl, rdata, dataLength));
}

dns::Message::~Message() {
	Answer *tmp = an;
	while(tmp) {
		tmp = tmp->next;
		delete an;
		an = tmp;
	}
}

void dns::getMessage(dns::Message *msg, void *buffer, size_t maxBuffSize) {

	char *currBuff = (char *)buffer;

	// header

	memcpy(&msg->h, currBuff, DNS_SIZEOF_HEADER);
	currBuff += DNS_SIZEOF_HEADER;


	// query

	msg->q.name = currBuff;
	currBuff += msg->q.name.length() + 1;

	memcpy(&msg->q.qtc, currBuff, DNS_SIZEOF_TYPE);
	currBuff += DNS_SIZEOF_TYPE;

}

size_t dns::createResponseBuffer(dns::Message &msg, void *buffer, size_t maxBuffSize) {

	char *currBuff = (char *)buffer;
	size_t buffSize = 0;

#define BUFOFFS (currBuff + buffSize)

	// header

	memcpy(BUFOFFS, reinterpret_cast<void*>(&msg.h), DNS_SIZEOF_HEADER);
	buffSize += DNS_SIZEOF_HEADER;


	// query

	strcpy_s(BUFOFFS, msg.q.name.length() + 1, msg.q.name.c_str());
	buffSize += msg.q.name.length() + 1;

	memcpy(BUFOFFS, reinterpret_cast<void *>(&msg.q.qtc), DNS_SIZEOF_TYPE);
	buffSize += DNS_SIZEOF_TYPE;


	// answer

	const Answer *curr = msg.getFirstAn();
	while(curr) {
		size_t size = curr->isExt() ? 2 : curr->name.length() + 1;
		memcpy(BUFOFFS, curr->name.c_str(), size);
		buffSize += size;

		memcpy(BUFOFFS, reinterpret_cast<const void *>(&curr->rr), DNS_SIZEOF_RR);
		buffSize += DNS_SIZEOF_RR;

		memcpy(BUFOFFS, curr->getRData()->data, curr->getRData()->len);
		buffSize += curr->getRData()->len;

		curr = curr->getNext();
	}

	return buffSize;

}


const char *util::getDotName(char *buffer, size_t maxBuffSize, const char *netName) {
	const char *trimName = netName[0] < 32 ? netName + 1 : netName;
	size_t netNameLen = strlen(trimName);
	if(netNameLen >= maxBuffSize) return "";
	strcpy_s(buffer, netNameLen + 1, trimName);
	for(int i = 0; i < netNameLen; i++) if(buffer[i] < 32) buffer[i] = '.';
	return buffer;
}

const char *util::getReqType(char *buffer, size_t maxBuffSize, ushort type) {
	switch(type) {
	case T_A: return "A";
	case T_CNAME: return "CNAME";
	case T_MX: return "MX";
	case T_NS: return "NS";
	case T_PTR: return "PTR";
	case T_SOA: return "SOA";
	default: return "";
	}
}