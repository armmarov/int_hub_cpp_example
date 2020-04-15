#include <iostream>
#include <curl/curl.h>
#include <string.h>

#include "blockchain.h"
#include "encryption.cpp"

#define IDX_FOR_TRUE_RETURN 11
#define IDX_FOR_PUBLICKEY_RETURN 12
#define ADMIN_ADDR "0x21C2FA9a2779b94D610f807daB838E17725B30A3"
#define ADMIN_PASS "testobc123"
#define CONTRACT_ADDR "0xE6673A9e4832D539c58AB1DdBDE952C19F326cD1"

const std::string m_contractAddr = "0xE6673A9e4832D539c58AB1DdBDE952C19F326cD1";
const std::string m_adminAddr = "0x21C2FA9a2779b94D610f807daB838E17725B30A3";
const std::string m_server_pubkey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC407pBSKDb6vsSkiNadIjOrNjA\nlMuTIMVlaCUo/coEBa+fNfzSm91eqCcrT/GI6j7m0zBJWcPGUjKNUG3l5dVLS0Jm\nf4uWgmXtWNF0of2TPU1XzBJUHlCBpkMXvdkJQfwpXV395Lu1F0Qyl6jpf/bEeJnE\nu2XsZk/OJPYHAAg7DQIDAQAB\n-----END PUBLIC KEY-----";
const std::string m_client_pubkeytest = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUQODnt7VZq5v9qOqQFzuzpl85\ntuow2o4ouKLckPDqn7ulTj/VuQKJzHcMR88e/U2VO7MX78YmfqRVwIHtJKEx2N3e\nY1CX7sKvzBxKAzJmdkQjrsbgd2Jv5989Z8TawijazIkfqiM49CTQ2+siGqWK+ysn\nNhqfxzLHIa/ey8B6VwIDAQAB\n-----END PUBLIC KEY-----";
const std::string m_client_pubkey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUQODnt7VZq5v9qOqQFzuzpl85tuow2o4ouKLckPDqn7ulTj/VuQKJzHcMR88e/U2VO7MX78YmfqRVwIHtJKEx2N3eY1CX7sKvzBxKAzJmdkQjrsbgd2Jv5989Z8TawijazIkfqiM49CTQ2+siGqWK+ysnNhqfxzLHIa/ey8B6VwIDAQAB-----END PUBLIC KEY-----";
const std::string m_client_privkey = "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJRA4Oe3tVmrm/2o\n6pAXO7OmXzm26jDajii4otyQ8Oqfu6VOP9W5AonMdwxHzx79TZU7sxfvxiZ+pFXA\nge0koTHY3d5jUJfuwq/MHEoDMmZ2RCOuxuB3Ym/n3z1nxNrCKNrMiR+qIzj0JNDb\n6yIapYr7Kyc2Gp/HMschr97LwHpXAgMBAAECgYEAh73Xr5KPY6kzTNAq5P/A1D7T\nFd8bEtwqKbLUu6uiStEyWKsK279oSY+CuSXOyQsYzDk7RAFwprJx+WooDF/rjnRf\nAyRUhIW6BLl0DPomYgU5rYHPF1gM1Nqc665nX8bbojEfnIbjr5DnOBQ3VXzeIHU/\n8S3uvLrbAnk9W8bX1qECQQDn07iE8TlsgtXxy2aLCQXCaBpmg8uny7XmDDIEYYmK\naqB4g4F9Q400N/HaE+HeL7brxkDULQgXSmzqi+sLSbDJAkEAo7ZIxPBMWcKvpRZJ\nH97JPFRMZqTF9RaZWN+r2loROSC7GOApailfXUuEiiqw+ZfGAFL2e94AOGTwIUfr\ntp6CHwJAM79x79L803j9EsUpdZ2k+HlOc1W2DxWM2/Ya8Blpn0kf2ubX78M1cNOQ\nG/LWN0eFWGnfrL0EklZdq5lh9RoU6QJASmXxhgZKPFR8bALHsoMVYqRQoCjriWj+\nwWPMfouF3jdgr3pXd9Zbb1N9ZSjnilYN9mG9gCcwZHCCrC06EqDQMwJAbtuuSV/0\nbJSX4j0J8l+g/Sq4p82wgz41NRqat3sYclqK+ahzy1nes35qJcSQVA8Ke4bWn3pe\nwLLVm3BhIOzsSA==\n-----END PRIVATE KEY-----";

unsigned char* encKey;

// Variables for curl
CURL *m_curl;
CURLcode m_res;

Blockchain* Blockchain::m_pInstance = NULL;

Blockchain* Blockchain::GetInstance(void)
{
	if(m_pInstance == NULL) {
		m_pInstance = new Blockchain;
	}
	return m_pInstance;
}

Blockchain::Blockchain()
{
	m_curl = curl_easy_init();
	init();
}

Blockchain::~Blockchain()
{
	curl_easy_cleanup(m_curl);
	m_pInstance = NULL;
}

void Blockchain::init()
{
	access_token = "";
	client_pubkey = "";
	client_privkey = "";

	client_private_key = createRSA((unsigned char*)m_client_privkey.c_str(), 0);
	server_public_key = createRSA((unsigned char*)m_server_pubkey.c_str(), 1);

	// Assymmetric encryption decryption
	std::string key = "\"";
	key.append(CLIENT_KEY);
	key.append("\"");
	encKey = new unsigned char[ENC_LENGTH];
	int enclen = public_encrypt(key.length(), (unsigned char*)key.c_str(), encKey, server_public_key);
	std::cout << "Key length:" << enclen << std::endl;
	if(enclen > 0) {
		std::cout << "Key encryption successfully" << std::endl;
	}
}

bool Blockchain::registerToken()
{
	std::string response;

	if(m_curl) {
		response = getApiWithHeaders((char*)"https://integrationhub.okwave.global/api/registerToken");

		if(response.find("true") == IDX_FOR_TRUE_RETURN) {
			access_token = response.substr(64, 145);
			std::cout << "Token: " << access_token << std::endl;
			return true;
		}
	}

	std::cout << "Cannot register token !!" << std::endl;
	return false;
}

bool Blockchain::generateKey()
{
	std::string response;

	if(m_curl && !access_token.empty()) {

		response = getApiWithHeaders((char*)"https://integrationhub.okwave.global/api/generateKey");		
		
		if(response.find("publicKey") == IDX_FOR_PUBLICKEY_RETURN) {
			client_pubkey = response.substr(24, 276);
			std::cout << "Pub Key: " << client_pubkey << std::endl;

			client_privkey = response.substr(316, 930);
			std::cout << "Priv Key: " << client_privkey << std::endl;

			return true;
		}
	}

	std::cout << "Error while generating keys" << std::endl;
	return false;
}

std::string Blockchain::createAccounts(char* id)
{
	std::string url = "https://integrationhub.okwave.global/api/ethtestnetthor/web3.eth.personal/newAccount";
	unsigned char* encMsg = new unsigned char[ENC_LENGTH];
	unsigned char* encMsgBin = new unsigned char[ENC_LENGTH];
	std::string content = "{\"password\":\"";
	content.append(id);
	content.append("\"}");

	// Encrypt message
	int len = encryptAES(CLIENT_KEY, content, encMsg);

	std::string toSend = "{\"encryptedkey\": \"";
	toSend.append(base64_encode(encKey, ENC_LENGTH) );
	toSend.append("\",\"encrypteddata\":\"");
	toSend.append(strToHex(encMsg, len));
	toSend.append("\",\"publickey\":\"");
	toSend.append(m_client_pubkey);
	toSend.append("\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);
	std::size_t encrypteddata_start = response.find("encrypteddata") + 16;
	std::size_t encrypteddata_end = response.find("encryptedkey") - 3;
	std::size_t encryptedkey_start = response.find("encryptedkey") + 15;
	std::size_t encryptedkey_end = response.length() - 3;

	std::string encrypteddata = response.substr(encrypteddata_start, encrypteddata_end - encrypteddata_start);
	std::string encryptedkey = response.substr(encryptedkey_start, encryptedkey_end - encryptedkey_start);

	std::cout << "encrypteddata: " << encrypteddata << std::endl;
	std::cout << "encryptedkey: " << encryptedkey << std::endl;

	unsigned char* decKey = new unsigned char[32];
	int declen = private_decrypt(RSA_size(client_private_key), (unsigned char*)base64_decode(encryptedkey).c_str(), decKey, client_private_key);
	std::cout << "enclen: " << declen << std::endl;
	std::cout << "decKey: " << decKey << std::endl;

	hexToBin(encrypteddata.c_str(), (char*)encMsgBin);
	std::string decMsg = decryptAES(decKey, encMsgBin);

	std::cout << "decMsg: " << decMsg << std::endl;

	return decMsg;
}

bool Blockchain::unlockAccounts(char* addr, char* pass)
{
	std::string url = "https://integrationhub.okwave.global/api/ethtestnetthor/web3.eth.personal/unlockAccount";
	unsigned char* encMsg = new unsigned char[ENC_LENGTH];
	unsigned char* encMsgBin = new unsigned char[ENC_LENGTH];

	std::string content = "{\"address\":\"";
	content.append(addr);
	content.append("\", \"password\": \"");
	content.append(pass);
	content.append("\", \"unlockDuration\": 15000}");

	// Encrypt message
	int len = encryptAES(CLIENT_KEY, content, encMsg);

	std::string toSend = "{\"encryptedkey\": \"";
	toSend.append(base64_encode(encKey, ENC_LENGTH) );
	toSend.append("\",\"encrypteddata\":\"");
	toSend.append(strToHex(encMsg, len));
	toSend.append("\",\"publickey\":\"");
	toSend.append(m_client_pubkey);
	toSend.append("\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);
	std::cout << response << std::endl;

	return true;
}

bool Blockchain::createCandidate(char* name, char* id, char* group, char* address)
{
	return false;
}

bool Blockchain::createVoter(char* name, char* id, char* address)
{
	std::string url = "https://integrationhub.okwave.global/api/eththor/id=2";
	
	std::string toSend = "{\"contractAddress\": \"";
	toSend.append(CONTRACT_ADDR);
	toSend.append("\", \"from\":\"");
	toSend.append(ADMIN_ADDR);
	toSend.append("\",\"method\":\"addToVoter(\'");
	toSend.append(name);
	toSend.append("\',\'");
	toSend.append(id);
	toSend.append("\',\'");
	toSend.append(address);
	toSend.append("\'\", \"gasPrice\": \"200000\", \"gasLimit\": \"6000000\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);

	std::cout << response << std::endl;

	return false;
}

bool Blockchain::getAllVoters()
{
	std::string url = "https://integrationhub.okwave.global/api/eththor/id=1";
	
	std::string toSend = "{\"contractAddress\": \"";
	toSend.append(CONTRACT_ADDR);
	toSend.append("\", \"from\":\"");
	toSend.append(ADMIN_ADDR);
	toSend.append("\",\"method\":\"getAllVoters()\",");
	toSend.append("\"gasPrice\": \"200000\", \"gasLimit\": \"6000000\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);

	std::cout << response << std::endl;

	return false;
}

size_t Blockchain::writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

std::string Blockchain::getApi(char* url) 
{

	std::string readBuffer;

	curl_easy_setopt(m_curl, CURLOPT_URL, url);
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &readBuffer);
	m_res = curl_easy_perform(m_curl);

	return readBuffer;
}

std::string Blockchain::getApiWithHeaders(char* url) 
{

	std::string readBuffer;
	std::string auth = "Authorization: OBC " + access_token;
	struct curl_slist* headers = NULL;

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, auth.c_str());

	curl_easy_setopt(m_curl, CURLOPT_URL, url);
	curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &readBuffer);
	m_res = curl_easy_perform(m_curl);

	return readBuffer;
}

std::string Blockchain::postApiWithHeaders(char* url, std::string postdata) 
{
	std::cout << url << std::endl;
	std::cout << postdata << std::endl;

	std::string readBuffer;
	std::string auth = "Authorization: OBC " + access_token;
	struct curl_slist* headers = NULL;

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, auth.c_str());

	curl_easy_setopt(m_curl, CURLOPT_URL, url);
	curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, postdata.c_str());
	curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, postdata.length());
	curl_easy_setopt(m_curl, CURLOPT_POST, 1);
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &readBuffer);
	m_res = curl_easy_perform(m_curl);

	if(m_res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(m_res));
		return "Error";
	}

	std::cout << readBuffer << std::endl;
	return readBuffer;
}

#ifdef UNIT_TEST
int main() {

	std::string id = "1231321";

	Blockchain::GetInstance()->registerToken();
	// Blockchain::GetInstance()->generateKey();
	Blockchain::GetInstance()->unlockAccounts((char*)ADMIN_ADDR, (char*)ADMIN_PASS);
	std::string addr = Blockchain::GetInstance()->createAccounts((char*) id.c_str());
	// Blockchain::GetInstance()->createVoter((char*)"Ammar", (char*)"811225334455", (char*)addr.c_str());
	Blockchain::GetInstance()->getAllVoters();

	return 0;

}
#endif