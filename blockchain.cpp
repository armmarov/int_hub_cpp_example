#include <iostream>
#include <curl/curl.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>

#include "blockchain.h"

#define IDX_FOR_TRUE_RETURN 11
#define IDX_FOR_PUBLICKEY_RETURN 12
#define AES_KEYLENGTH 256

const std::string m_contractAddr = "0xE6673A9e4832D539c58AB1DdBDE952C19F326cD1";
const std::string m_adminAddr = "0x21C2FA9a2779b94D610f807daB838E17725B30A3";
const std::string m_server_pubkey = "-----BEGIN PUBLIC KEY-----\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC407pBSKDb6vsSkiNadIjOrNjA\
lMuTIMVlaCUo/coEBa+fNfzSm91eqCcrT/GI6j7m0zBJWcPGUjKNUG3l5dVLS0Jm\
f4uWgmXtWNF0of2TPU1XzBJUHlCBpkMXvdkJQfwpXV395Lu1F0Qyl6jpf/bEeJnE\
u2XsZk/OJPYHAAg7DQIDAQAB\
-----END PUBLIC KEY-----";

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
}


bool Blockchain::registerToken()
{
	std::string response;

	if(m_curl) {
		response = getApiWithHeaders((char*)"https://integrationhub.okwave.global/api/registerToken");

		// std::cout << "Response: " << response << std::endl;

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

		// std::cout << "Response: " << response << std::endl;
		
		if(response.find("publicKey") == IDX_FOR_PUBLICKEY_RETURN) {
			client_pubkey = response.substr(24, 278);
			std::cout << "Pub Key: " << client_pubkey << std::endl;

			client_privkey = response.substr(315, 931);
			std::cout << "Priv Key: " << client_privkey << std::endl;

			return true;
		}
	}

	std::cout << "Error while generating keys" << std::endl;
	return false;
}

bool Blockchain::createCandidate(char* name, char* id, char* group, char* address)
{
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
	std::string auth = "Authorization: " + access_token;
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

std::string Blockchain::decryptAES(std::string key, unsigned char* enc_msg) 
{
	size_t len = sizeof(enc_msg);
    unsigned char aes_key[AES_KEYLENGTH];
    memset(aes_key, 0, AES_KEYLENGTH/8);
    strcpy((char*) aes_key, key.c_str());

	/* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

	// buffers for encryption and decryption
	const size_t encslength = ((len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char dec_out[len];
    memset(dec_out, 0, sizeof(dec_out));

    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, AES_KEYLENGTH, &dec_key);
    AES_cbc_encrypt(enc_msg, dec_out, encslength, &dec_key, iv, AES_DECRYPT);

	std::stringstream ss;
    for(int i = 0; i < encslength; i++)
    {
        ss << dec_out[i];
    }

	return ss.str();
}

bool Blockchain::encryptAES(std::string key, std::string msg, unsigned char* enc_out) 
{
	size_t inputslength = msg.length();
	unsigned char aes_input[inputslength];
    unsigned char aes_key[AES_KEYLENGTH];
	memset(aes_input, 0, inputslength/8);
    memset(aes_key, 0, AES_KEYLENGTH/8);
    strcpy((char*) aes_input, msg.c_str());
    strcpy((char*) aes_key, key.c_str());

	/* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

	// buffers for encryption and decryption
    memset(enc_out, 0, sizeof(enc_out));

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, AES_KEYLENGTH, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv, AES_ENCRYPT);

	return true;
}

bool Blockchain::testCall()
{
	std::string key = "990823013344";
	std::string msg = "item to encrypt";
	unsigned char* enc_msg;
	encryptAES(key, msg, enc_msg);
	std::string dec_msg = decryptAES(key, enc_msg);
	std::cout << dec_msg << std::endl; 
	return false;
}

#ifdef UNIT_TEST
int main() {

	Blockchain::GetInstance()->registerToken();
	Blockchain::GetInstance()->generateKey();
	Blockchain::GetInstance()->testCall();

	return 0;

}
#endif