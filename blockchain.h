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
    bool unlockAccounts(char* addr, char* pass);

    bool createCandidate(char* name, char* id, char* group, char* address);
    bool createVoter(char* name, char* id, char* address);

    bool removeCandidate(char* address);
    bool removeVoter(char* address);

    bool getCandidateByID(char* id);
    bool getVoterByID(char* id);

    bool getAllCandidates();
    bool getAllVoters();

    bool registerEvent(char* name, char* location, uint32_t date, uint8_t period);
    bool getEvent(char* name);
    bool getCandidateByEvent(char* id);
    bool addCandidateToEvent(char* address);
    bool removeCandidateFromEvent(char* address);

    bool castVoting(char* candidate, char* id);
    bool getResultByCandidate(char* candidate, char* id);

    bool testCall();

private:

	Blockchain();
	~Blockchain();

	static Blockchain* m_pInstance;

    // Private Variables
    std::string access_token;
    std::string client_pubkey;
    std::string client_privkey;

    // Private Functions
    void init();
	static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp);
    std::string getApi(char* url);
    std::string getApiWithHeaders(char* url);
    std::string postApiWithHeaders(char* url, std::string postdata);
};

#endif