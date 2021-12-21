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

namespace {
	char strBuffer[MAX_BUFFER_SIZE] = { 0 };
	char msgBuffer[MAX_BUFFER_SIZE] = { 0 };
}

int main(int argc, const char *argv[]) {

	Mem e;

	conf::loadEntryTable();

	WSAData wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)) LOG("[error] WSA init");

	SOCKET sockServ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockServ == INVALID_SOCKET) LOG("[error] socket init");

	sockaddr_in servAddr;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(53);


	if(bind(sockServ, reinterpret_cast<SOCKADDR *>(&servAddr), sizeof(servAddr)) == SOCKET_ERROR) LOG("[error] binding");

	sockaddr_in si_other;
	int otherLen = sizeof(si_other);

	while(1) {

		// recv & parse msg
		recvfrom(sockServ, msgBuffer, MAX_BUFFER_SIZE, 0, (SOCKADDR *)&si_other, &otherLen);

		dns::Message req;
		dns::getMessage(&req, msgBuffer);

		LOG("request from %s; requesting %s (%s)",
			inet_ntop(AF_INET, &si_other.sin_addr, strBuffer + 500, MAX_BUFFER_SIZE - 500),
			util::getDotName(strBuffer, MAX_BUFFER_SIZE, req.q.name.c_str() + 1),
			util::getReqType(strBuffer, MAX_BUFFER_SIZE, ntohs(req.q.qtc.qtype)));


		// respond if found entry
		conf::Entry foundEntry;
		if(conf::findEntry(&foundEntry, req.q.name.c_str())) {

			{
				in_addr ntop;
				ntop.S_un.S_addr = foundEntry.A;
				LOG("FOUND %s WITH ADDR %s",
					util::getDotName(strBuffer, MAX_BUFFER_SIZE, req.q.name.c_str()),
					inet_ntop(AF_INET, &ntop, strBuffer + 500, MAX_BUFFER_SIZE - 500));
			}

			//LOG("responding");

			dns::Message resp;

			resp.h = req.h;
			resp.h.f.qr = 1;
			resp.h.anCount = htons(2);

			resp.q = req.q;

			dns::Answer *before = resp.addAnswer("", T_CNAME, 0xff000000, "\x8""abgzawaw\x4yoru", 15)->extend(nullptr);

			before = resp.addAnswer("", T_A, 0xff000000, reinterpret_cast<const void *>(&foundEntry.A), 4)->extend(before);

			/*resp.an = new dns::Answer(resp.q.name.c_str());
			resp.an->rdata = reinterpret_cast<void *>(&foundEntry.A);*/

			size_t retSize = dns::createResponseBuffer(resp, msgBuffer, MAX_BUFFER_SIZE);

			//LOG("sending");

			if(sendto(sockServ, msgBuffer, static_cast<int>(retSize), 0, (struct sockaddr *)&si_other, sizeof(si_other)) == SOCKET_ERROR) LOG("[error] sending (%i)", WSAGetLastError());
		}
	}


	LOG("closing %i", WSAGetLastError());

	closesocket(sockServ);

	WSACleanup();

}