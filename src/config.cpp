#include "dns.h"
#include "incl.h"

conf::Entry *entryTable = nullptr;
unsigned long long nEntr = 0;

void conf::loadEntryTable() {

	// mock

	nEntr = 5;
	entryTable = new conf::Entry[nEntr];
	
	entryTable[0].name = "\6google\2pl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[0].A);

	entryTable[1].name = "\4lolz\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[1].A);

	entryTable[2].name = "\4helo\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[2].A);

	entryTable[3].name = "\5helo2\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[3].A);

	entryTable[4].name = "\4sike\6blblbl";
	InetPton(AF_INET, L"192.168.8.100", &entryTable[4].A);

}

conf::Entry *conf::getEntry(unsigned long long index) { return &entryTable[index]; }

conf::Entry *conf::findEntry(const char *name) {
	for(ullong i = 0; i < nEntr; i++)
		if(!strcmp(entryTable[i].name, name)) return entryTable + i;
	return nullptr;
}



