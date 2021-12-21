#include "dns.h"
#include "incl.h"

#include "Ini-file-parser/src/parseIni.h"

ini::File entryTable;

namespace {
	char strBuffer[MAX_BUFFER_SIZE] = { 0 };
}

conf::Entry::~Entry() {
	if(name) delete[]name;
}

void conf::loadEntryTable() {

	{
		char *confPath = nullptr;
		size_t buffCount = 0;
		bool error = false;
		int err = _dupenv_s(&confPath, &buffCount, "CONFIG");
		if(!err) {
			char iniPath[_MAX_PATH];
			int written = snprintf(iniPath, _MAX_PATH, "%sdns.ini", confPath);
			if(written < 0 || written >= _MAX_PATH || !entryTable.load(iniPath))
				error = true;
		} else error = true;
		delete[]confPath;
		if(error) {
			LOG("[error] loadEntryTable");
			while(!entryTable.isOK()) {
				ini::ErrorInfo e = entryTable.getError();
				LOG("[error] ini loader: (%u) %s", e.code, e.description);
			}
		}
	}

}

bool conf::getEntry(conf::Entry *entr, unsigned long long index) {
	return false;
}

bool conf::findEntry(conf::Entry *entr, const char *name) {
	ini::Section *domain = entryTable.section(util::getDotName(strBuffer, MAX_BUFFER_SIZE, name));
	if(!domain) return false;

	if(ini::Attrib *A = domain->get("A")) InetPtonA(AF_INET, A->value.c_str(), &entr->A);

	return true;
}



