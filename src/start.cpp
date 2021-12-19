#include "dns.h"
#include "incl.h"

#pragma region memory tracking
size_t total_allocated = 0;
struct Mem {
	~Mem() {
		LOG("total allocated: %zu", total_allocated);
	};
};
//#define MEM_LOG

_NODISCARD _Ret_notnull_ _Post_writable_byte_size_(_Size) _VCRT_ALLOCATOR
void *__CRTDECL operator new(size_t _Size) {
	total_allocated += _Size;
#ifdef MEM_LOG
	LOG("alloc %i", _Size);
#endif

	if(void *ptr = std::malloc(!_Size ? 1 : _Size))
		return ptr;

	throw std::bad_alloc{};
}
#pragma endregion


void loadEntryTable();
dns::Entry *getEntry(unsigned long long index);
uint findEntry(const char *name);

int main(int argc, const char *argv[]) {

	Mem e;

	loadEntryTable();

	WSAData wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)) LOG("[error] WSA init");

	SOCKET sockServ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockServ == INVALID_SOCKET) LOG("[error] socket init");

	sockaddr_in servAddr;
	//InetPton(AF_INET, L"127.0.0.1", &servAddr.sin_addr);
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(53);

	char reqName[1000];

	if(bind(sockServ, reinterpret_cast<SOCKADDR *>(&servAddr), sizeof(servAddr)) == SOCKET_ERROR) LOG("[error] binding");

	char buf[1000];
	sockaddr_in si_other;
	int otherLen = sizeof(si_other);

	while(1) {
		recvfrom(sockServ, buf, 1000, 0, (SOCKADDR *)&si_other, &otherLen);

		dns::Message req;
		dns::getMessage(&req, buf);

		strcpy_s(reqName, 1000, req.q.name + 1);
		for(int i = 0; i < 1000 && reqName[i] != 0; i++) if(reqName[i] < 32) reqName[i] = '.';
		LOG("request from %u; requesting %s", ntohl(si_other.sin_addr.s_addr), reqName);

		uint addr = findEntry(req.q.name);
		if(addr) LOG("FOUND %s WITH ADDR %i", req.q.name, addr);

		LOG("responding");

		dns::Message resp;
		resp.h = req.h;
		resp.h.f.qr = 1;
		resp.h.anCount = htons(1);

		resp.q.name = new char[strlen(req.q.name) + 1];
		strcpy_s(resp.q.name, strlen(req.q.name) + 1, req.q.name);

		resp.q.qtc = req.q.qtc;
		resp.q.len = req.q.len;

		resp.an = new dns::Answer;
		resp.an->name = resp.q.name;
		resp.an->rr.dataLength = htons(sizeof(int));
		resp.an->rr.qtc = req.q.qtc;
		resp.an->rr.ttl = 0xff000000; // (int)(htons(3600)) << 16;

		resp.an->rdata = (char *)new int;
		*(reinterpret_cast<int *>(resp.an->rdata)) = addr;

		size_t retSize = dns::createResponse(resp, buf, 1000);

		LOG("sending");

		if(sendto(sockServ, buf, retSize, 0, (struct sockaddr *)&si_other, retSize) == SOCKET_ERROR) {
			printf("sendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
	}


	LOG("closing %i", WSAGetLastError());

	closesocket(sockServ);

	WSACleanup();

}