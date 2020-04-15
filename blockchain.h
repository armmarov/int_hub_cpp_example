#ifndef __CHIP_READER_H__
#define __CHIP_READER_H__

#include <stdint.h>
#include <string.h>

class Blockchain {

public:

	static Blockchain* GetInstance(void);

    // Public Functions
    bool registerToken();
    bool generateKey();
    std::string createAccounts(char* id);
    std::string getBalance(char* addr);
    bool unlockAccounts(char* addr, char* pass);    

    bool addToVoter(char* name, char* id, char* address);
    bool getAllVoters();

private:

	Blockchain();
	~Blockchain();

	static Blockchain* m_pInstance;

    // Private Variables
    std::string access_token;
    std::string client_pubkey;
    std::string client_privkey;
    std::string server_pubkey;

    // Private Functions
    void init();
	static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp);
    std::string getApi(char* url);
    std::string getApiWithHeaders(char* url);
    std::string postApiWithHeaders(char* url, std::string postdata);
};

#endif