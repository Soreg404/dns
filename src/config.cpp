#include "dns.h"
#include "incl.h"

dns::Entry *entryTable = nullptr;
unsigned long long nEntr = 0;

void loadEntryTable() {

	// mock

	nEntr = 5;
	entryTable = new dns::Entry[nEntr];
	
	entryTable[0].name = "\6google\2pl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[0].ipv4);

	entryTable[1].name = "\4lolz\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[1].ipv4);

	entryTable[2].name = "\4helo\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[2].ipv4);

	entryTable[3].name = "\5helo2\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[3].ipv4);

	entryTable[4].name = "\4sike\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[4].ipv4);

}

dns::Entry *getEntry(unsigned long long index) { return &entryTable[index]; }

uint findEntry(const char *name) {
	for(ullong i = 0; i < nEntr; i++)
		if(!strcmp(entryTable[i].name, name)) return entryTable[i].ipv4;
	return 0;
}



