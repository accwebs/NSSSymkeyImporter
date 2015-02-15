/*
 * NSSSymkeyImporter.cpp - See NSSSymkeyImporter.h
 * 
 */

// ---------------------------------------------------------------------------------------------

#include "NSSSymkeyImporter.h"

#include <nspr.h>

#include <memory>
#include <sstream>
#include <iostream>

//----------------------------------------------------------------------
// PUBLIC STATIC
// program constants
const std::string PROGRAM_NAME("NSS Symkey Importer");
const std::string PROGRAM_EXECUTABLE("NSSSymkeyImporter.exe");
const std::string PROGRAM_VERSION("1.0");
const std::string PROGRAM_DESCRIPTION(std::string("Permanently imports a symmetric NSS 2-key 3DES key into an NSS database."));

// ---------------------------------------------------------------------------------------------
// global variable for NSS password
std::string s_nssPassword;

// ---------------------------------------------------------------------------------------------
// Initializes the NSS library
void init_nss(const std::string& dbdir, const std::string& dbpass){
    SECStatus rv;
    PK11SlotInfo *slot = nullptr;
    PRUint32 flags = 0;

    s_nssPassword = dbpass;


    // Initialize NSPR
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    

    // Initialize NSS
    PK11_SetPasswordFunc(nss_password_function);
    rv = NSS_Initialize(dbdir.c_str(), "", "", "", flags);
    if (rv != SECSuccess){
        throw std::runtime_error(build_nss_error_string("NSS_Initialize() failed"));
    }
    

    // get internal key slot
    slot = PK11_GetInternalKeySlot();
    if (slot == nullptr){
        throw std::runtime_error(build_nss_error_string("Unable to get key slot."));
    }
    try{

        // initialize slot
        if (PK11_NeedUserInit (slot)) {
            rv = PK11_InitPin(slot, nullptr, dbpass.c_str());
            if (rv != SECSuccess) {
                throw std::runtime_error(build_nss_error_string("PK11_InitPin() failed"));
            }
        }

        // log in to slot
        if (PK11_NeedLogin(slot)) {
            rv = PK11_Authenticate(slot, PR_TRUE, nullptr);
            if (rv != SECSuccess) {
                throw std::runtime_error(build_nss_error_string("PK11_Authenticate failed"));
            }
        }
    
        PK11_FreeSlot(slot);
        slot = nullptr;
    }catch(...){
        PK11_FreeSlot(slot);
        slot = nullptr;

        throw;
    }
}

// ---------------------------------------------------------------------------------------------
// shuts down NSS
void shutdown_nss(){
    SECStatus s = NSS_Shutdown();
    if (s != SECSuccess){
        throw std::runtime_error("Internal error - NSS_Shutdown() failed.  Possible NSS memory/handle leak?");
    }
}

// ---------------------------------------------------------------------------------------------
// NSS helper functions
static char* nss_password_function(PK11SlotInfo* slot, PRBool retry, void *arg){
    return PL_strdup (s_nssPassword.c_str());
}
std::string build_nss_error_string(const std::string& prefix){
    PRInt32 errlen = PR_GetErrorTextLength();
    std::shared_ptr<char> msgBuf(new char[errlen+1]);
    memset(msgBuf.get(),0x00,errlen+1);
    PR_GetErrorText(msgBuf.get());
    PRErrorCode err = PR_GetError();

    std::ostringstream msg;
    msg << prefix << ": Error " << err << " (" << msgBuf.get() << ")";
    return msg.str();
}

PK11SlotInfo* nss_getSlot(const char* const slotName){
    PK11SlotInfo* slot = nullptr;
    if (slotName == nullptr){
        return nullptr;
    }
    if (strlen(slotName) == 0){
        return nullptr;
    }
    if ((strcmp(slotName, "internal") == 0) || (strcmp(slotName, "NSS Internal Cryptographic Services") == 0)){
        slot = PK11_GetInternalKeySlot();
    }else{
        slot = PK11_FindSlotByName(slotName);
    }
    return slot;
}

// ---------------------------------------------------------------------------------------------
// Locates the symkey with the specified nickname on the specified slot
// params:
//   PK11SlotInfo* slot - Slot to search for the specified key nickname.
//   const char* const keyNickname - Name of key to retrieve.  Nicknames are case sensitive.
// returns:
//   non - nullptr if success
//   nullptr if could not locate key
PK11SymKey* nss_getSymkeyByName(PK11SlotInfo* slot, const char* const keyNickname){
    char* thisKeyName = nullptr;
    PK11SymKey* symkeyList = nullptr;
    PK11SymKey* thisSymKey = nullptr;
    PK11SymKey* nextSymKey = nullptr;
    PK11SymKey* foundSymKey = nullptr;

    /* check for null inputs */
    if ((keyNickname == nullptr) || (slot == nullptr)){
        return nullptr;
    }

    /* initialize the symmetric key list. */
    symkeyList = PK11_ListFixedKeysInSlot(slot,       /* slot     */
                                          nullptr,    /* nickname */
                                          nullptr);   /* wincx    */

    /* iterate through the symmetric key list, searching for first key with specified name */
    thisSymKey = symkeyList;
    while (thisSymKey != nullptr){
        thisKeyName = PK11_GetSymKeyNickname(thisSymKey);
        if (thisKeyName != nullptr) {
            if (PL_strcmp(thisKeyName, keyNickname) == 0){
                PORT_Free(thisKeyName);
                break;
            } else{
                PORT_Free(thisKeyName);
            }
        }
        thisSymKey = PK11_GetNextSymKey(thisSymKey);
    }
    /* if thisSymKey != nullptr, we found a key with a matching name! */

    /* copy symkey reference of found symkey */
    /*   we need to do this because the symkey we found is a member of the returned list, which must be freed together inside this function */
    /*   we'll return the copy to the caller */
    if (thisSymKey != nullptr){
        foundSymKey = PK11_ReferenceSymKey(thisSymKey);
    }

    /* PK11_ListFixedKeysInSlot() returns a list of symkeys that need to be freed now */
    thisSymKey = symkeyList;
    while (thisSymKey != nullptr){
        nextSymKey = PK11_GetNextSymKey(thisSymKey);
        PK11_FreeSymKey(thisSymKey);
        thisSymKey = nextSymKey;
    }

    return foundSymKey;
}

// ---------------------------------------------------------------------------------------------
// Converts a string of ASCII-encoded hex to a byte array.
std::vector<BYTE> Convert_ASCIIHex_To_Byte(std::string str){
    // strip out any separator characters from this string
    StringReplaceAll(str, ":", "");
    StringReplaceAll(str, " ", "");

    std::vector<BYTE> result;

    std::stringstream converter;
    size_t pos = 1;
    while (pos < str.length()){
        // get two characters from string
        std::string twoChars(str.substr(pos - 1, 2));

        // convert two characters to int
        converter.clear();
        converter << std::hex << twoChars;
        int temp;
        converter >> temp;

        // check for conversion error
        if ((converter.fail() || converter.bad()) == true){
            std::ostringstream ss;
            ss << "Unable to convert ASCII-hex string \"" << str << "\" to byte array; failed on bytes " << (pos - 1) << "-" << pos << ": \"" << twoChars << "\". Is the input valid?";
            throw std::runtime_error(ss.str());
        }

        // save result
        result.push_back(static_cast<BYTE>(temp));
        
        // skip forward two characters
        pos += 2; 
    }

    return result;
}

// ---------------------------------------------------------------------------------------------
// replaces all instances of a string with a new string
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to){
    if (from.empty() == true){
        return;
    }
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos){
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

// ---------------------------------------------------------------------------------------------

void Import_Key_Permanent(const std::string& slotName, const std::string& keyName, const std::vector<BYTE>& keyData){

    // get slot
    PK11SlotInfo* slot = nss_getSlot(slotName.c_str());
    if (slot == nullptr){
        throw std::runtime_error(build_nss_error_string(std::string("Failed getting slot named \'") + slotName + "\'."));
    }
    try{
        
        // import the raw key data; this will NOT work with NSS in FIPS mode
        SECItem SECItemkey;
        SECItemkey.type = siBuffer;
        SECItemkey.data = const_cast<BYTE*>(&keyData.at(0));
        SECItemkey.len = keyData.size();
            
        PK11SymKey* importedKey = PK11_ImportSymKeyWithFlags(slot, CKM_DES2_KEY_GEN, PK11_OriginNULL, CKA_ENCRYPT, &SECItemkey, 0, PR_TRUE, nullptr);
        if (importedKey == nullptr){
            throw std::runtime_error(build_nss_error_string("Unable to directly import key data to NSS token using PK11_ImportSymKey."));
        }
        try{
            SECStatus rv = PK11_SetSymKeyNickname(importedKey, keyName.c_str());
            if (rv != SECSuccess) {
                throw std::runtime_error(build_nss_error_string("Unable to set symkey nickname."));
            }
            
            std::cout << "Import complete.\n"
                      << "You should verify the import by executing \'symkeyutil -d <dbdir> -L\'.\n";

            PK11_FreeSymKey(importedKey);
            importedKey = nullptr;

        }catch(...){
            // clean up
            PK11_DeleteTokenSymKey(importedKey);
            PK11_FreeSymKey(importedKey);
            importedKey = nullptr;

            throw;
        }
        
        // clean up
        PK11_FreeSlot(slot);
        slot = nullptr;
    }catch(...){
        // clean up
        PK11_FreeSlot(slot);
        slot = nullptr;

        throw;
    }
}

// ---------------------------------------------------------------------------------------------
int main(int argc, const char** const argv){
    int retcode;

    // if not 5 command line arguments
    if (argc != 5+1){
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << "\n"
                  << PROGRAM_DESCRIPTION << "\n"
                  << "\n"
                  << "Usage:  " << PROGRAM_EXECUTABLE << " <nss_db_dir> <nss_pin> <slot_name> <key_name>\n"
                  << "        <key_data>\n"
                  << "  nss_db_dir - Path to directory containing NSS database files.\n"
                  << "  nss_pin    - PIN / password for the NSS database.\n"
                  << "  slot_name  - Name of destination slot. Specify \'internal\' for internal token.\n"
                  << "  key_name   - Key nickname to assign to the imported key.\n"
                  << "  key_data   - Key data specified in ASCII-HEX format.\n";
        retcode = 1;
    
    // correct number of arguments
    }else{
        // print program name and version
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << "\n" << std::endl;

        // convert parameters to strings
        const std::string nss_dir(argv[1]);
        const std::string nss_pin(argv[2]);
        const std::string slot_name(argv[3]);
        const std::string key_name(argv[4]);
        const std::string key_data_str(argv[5]);

        // try to initialize NSS
        try{
            init_nss(nss_dir, nss_pin);
            
            try{
                // convert key data to vector of bytes
                std::vector<BYTE> key_data(Convert_ASCIIHex_To_Byte(key_data_str));
                
                // try to import key
                try{
                    Import_Key_Permanent(slot_name, key_name, key_data);
                    retcode = 0;
                    
                } catch (std::runtime_error& ex){
                    std::cout << "Exception thrown while importing key data: " << ((ex.what() == nullptr) ? "null" : ex.what())
                              << std::endl;
                    retcode = 100;
                } catch (...){
                    std::cout << "Unknown exception thrown while importing key data."
                              << std::endl;
                    retcode = 100;
                }
            
            // exception thrown converting ASCII-hex text
            } catch (std::runtime_error& ex){
                std::cout << "Exception thrown while processing key input data: " << ((ex.what() == nullptr) ? "null" : ex.what())
                          << std::endl;
                retcode = 75;
            } catch (...){
                std::cout << "Unknown exception thrown while processing key input data."
                          << std::endl;
                retcode = 75;
            }
            
            // shut down NSS
            try{
                shutdown_nss();
            } catch (std::runtime_error& ex){
                std::cout << "Exception thrown while shutting down NSS: " << ((ex.what() == nullptr) ? "null" : ex.what())
                          << std::endl;
            } catch (...){
                std::cout << "Unknown exception thrown while shutting down NSS."
                          << std::endl;
            }
            
        // exception thrown while initializing NSS
        }catch(std::runtime_error& ex){
            std::cout << "Exception thrown while initializing NSS: " << ((ex.what() == nullptr) ? "null" : ex.what())
                      << std::endl;
            retcode = 50;
        }catch(...){
            std::cout << "Unknown exception thrown while initializing NSS."
                      << std::endl;
            retcode = 50;
        }
    
    } // endif arguments are correct
    
    return retcode;
}

// ---------------------------------------------------------------------------------------------
