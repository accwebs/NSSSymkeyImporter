/*
 * NSSSymkeyImporter.h - Permanently imports a symmetric NSS 2-key 3DES key into an NSS database.
 * 
 */
// ---------------------------------------------------------------------------------------------

#ifndef NSSSymkeyImporter_H_
#define NSSSymkeyImporter_H_

// ---------------------------------------------------------------------------------------------

#include <string>
#include <stdexcept>
#include <vector>

#include <nss.h>
#include <pk11pub.h>

typedef unsigned char BYTE;

// ---------------------------------------------------------------------------------------------

// Initializes the NSS library 
void init_nss(const std::string& dbdir, const std::string& dbpass);
// shuts down NSS
void shutdown_nss();

// NSS helper functions
static char* nss_password_function(PK11SlotInfo* slot, PRBool retry, void *arg);
std::string build_nss_error_string(const std::string& prefix);
PK11SlotInfo* nss_getSlot(const char* const slotName);
PK11SymKey* nss_getSymkeyByName(PK11SlotInfo* slot, const char* const keyNickname);

std::vector<BYTE> Convert_ASCIIHex_To_Byte(std::string str);
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to);

void Import_Key_Permanent(const std::string& slotName, const std::string& keyName, const std::vector<BYTE>& keyData);

int main(int argc, const char** const argv);

// ---------------------------------------------------------------------------------------------

#endif

// ---------------------------------------------------------------------------------------------
