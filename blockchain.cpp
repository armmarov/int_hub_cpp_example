#include <iostream>
#include <curl/curl.h>
#include <string.h>

#include "blockchain.h"
#include "encryption.cpp"

#define IDX_FOR_TRUE_RETURN 		11
#define IDX_FOR_PUBLICKEY_RETURN 	12
#define VALID_ADDR_LEN 			42
#define ADMIN_ADDR 			"0x21C2FA9a2779b94D610f807daB838E17725B30A3"
#define ADMIN_PASS 			"testobc123"
#define CONTRACT_ADDR 			"0xE6673A9e4832D539c58AB1DdBDE952C19F326cD1"

#define IH_URL_BASIC 	"https://integrationhub.okwave.global/api"
#define IH_URL_SC 	IH_URL_BASIC "/eththor/id=1"
#define IH_URL_SC_PARAM IH_URL_BASIC "/eththor/id=2"
#define IH_URL_RT 	IH_URL_BASIC "/registerToken"
#define IH_URL_GK 	IH_URL_BASIC "/generateKey"
#define IH_URL_GB 	IH_URL_BASIC "/ethtestnetthor/web3.eth/getBalance"
#define IH_URL_CA 	IH_URL_BASIC "/ethtestnetthor/web3.eth.personal/newAccount"
#define IH_URL_UA 	IH_URL_BASIC "/ethtestnetthor/web3.eth.personal/unlockAccount"

#define SERVER_PUBKEY  "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC407pBSKDb6vsSkiNadIjOrNjA\nlMuTIMVlaCUo/coEBa+fNfzSm91eqCcrT/GI6j7m0zBJWcPGUjKNUG3l5dVLS0Jm\nf4uWgmXtWNF0of2TPU1XzBJUHlCBpkMXvdkJQfwpXV395Lu1F0Qyl6jpf/bEeJnE\nu2XsZk/OJPYHAAg7DQIDAQAB\n-----END PUBLIC KEY-----";
#define CLIENT_PUBKEY  "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUQODnt7VZq5v9qOqQFzuzpl85tuow2o4ouKLckPDqn7ulTj/VuQKJzHcMR88e/U2VO7MX78YmfqRVwIHtJKEx2N3eY1CX7sKvzBxKAzJmdkQjrsbgd2Jv5989Z8TawijazIkfqiM49CTQ2+siGqWK+ysnNhqfxzLHIa/ey8B6VwIDAQAB-----END PUBLIC KEY-----";
#define CLIENT_PRIVKEY "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJRA4Oe3tVmrm/2o\n6pAXO7OmXzm26jDajii4otyQ8Oqfu6VOP9W5AonMdwxHzx79TZU7sxfvxiZ+pFXA\nge0koTHY3d5jUJfuwq/MHEoDMmZ2RCOuxuB3Ym/n3z1nxNrCKNrMiR+qIzj0JNDb\n6yIapYr7Kyc2Gp/HMschr97LwHpXAgMBAAECgYEAh73Xr5KPY6kzTNAq5P/A1D7T\nFd8bEtwqKbLUu6uiStEyWKsK279oSY+CuSXOyQsYzDk7RAFwprJx+WooDF/rjnRf\nAyRUhIW6BLl0DPomYgU5rYHPF1gM1Nqc665nX8bbojEfnIbjr5DnOBQ3VXzeIHU/\n8S3uvLrbAnk9W8bX1qECQQDn07iE8TlsgtXxy2aLCQXCaBpmg8uny7XmDDIEYYmK\naqB4g4F9Q400N/HaE+HeL7brxkDULQgXSmzqi+sLSbDJAkEAo7ZIxPBMWcKvpRZJ\nH97JPFRMZqTF9RaZWN+r2loROSC7GOApailfXUuEiiqw+ZfGAFL2e94AOGTwIUfr\ntp6CHwJAM79x79L803j9EsUpdZ2k+HlOc1W2DxWM2/Ya8Blpn0kf2ubX78M1cNOQ\nG/LWN0eFWGnfrL0EklZdq5lh9RoU6QJASmXxhgZKPFR8bALHsoMVYqRQoCjriWj+\nwWPMfouF3jdgr3pXd9Zbb1N9ZSjnilYN9mG9gCcwZHCCrC06EqDQMwJAbtuuSV/0\nbJSX4j0J8l+g/Sq4p82wgz41NRqat3sYclqK+ahzy1nes35qJcSQVA8Ke4bWn3pe\nwLLVm3BhIOzsSA==\n-----END PRIVATE KEY-----";

unsigned char* m_encrypted_key;
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

/**
 * Initialize all variables and encypt asymmetric key.
 */
void Blockchain::init()
{
	access_token = "";
	client_pubkey = CLIENT_PUBKEY;
	client_privkey = CLIENT_PRIVKEY;
	server_pubkey = SERVER_PUBKEY;

	client_private_key = createRSA((unsigned char*)client_privkey.c_str(), 0);
	server_public_key = createRSA((unsigned char*)server_pubkey.c_str(), 1);

	// Asymmetric key encryption
	std::string key = "\"";
	key.append(CLIENT_KEY);
	key.append("\"");
	m_encrypted_key = new unsigned char[ENC_LENGTH];
	int enclen = public_encrypt(key.length(), (unsigned char*)key.c_str(), m_encrypted_key, server_public_key);
	std::cout << "Key length:" << enclen << std::endl;
	if(enclen > 0) {
		std::cout << "Key encryption successfully" << std::endl;
	}
}

/**
 * Public method to register token at Integration Hub.
 * @return true if ok
 */
bool Blockchain::registerToken()
{
	std::string response;

	if(m_curl) {
		response = getApiWithHeaders((char*)IH_URL_RT);

		if(response.find("true") == IDX_FOR_TRUE_RETURN) {
			access_token = response.substr(64, 145);
			std::cout << "Token: " << access_token << std::endl;
			return true;
		}
	}

	std::cout << "Cannot register token !!" << std::endl;
	return false;
}

/**
 * Public method to generate public/private key from Integration Hub.
 * @return true if ok
 */
bool Blockchain::generateKey()
{
	std::string response;

	if(m_curl && !access_token.empty()) {

		response = getApiWithHeaders((char*)IH_URL_GK);		
		
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

/**
 * Public method to create user account.
 * @param id is the id for account creation
 * @return The account address
 */
std::string Blockchain::createAccounts(char* id)
{
	if(id == "" || id == NULL) return "ID is not available.";

	std::string url = IH_URL_CA;
	unsigned char* encMsg = new unsigned char[ENC_LENGTH];
	unsigned char* encMsgBin = new unsigned char[ENC_LENGTH];
	std::string content = "{\"password\":\"";
	content.append(id);
	content.append("\"}");

	// Encrypt message
	int len = encryptAES(CLIENT_KEY, content, encMsg);

	std::string toSend = "{\"encryptedkey\": \"";
	toSend.append(base64_encode(m_encrypted_key, ENC_LENGTH) );
	toSend.append("\",\"encrypteddata\":\"");
	toSend.append(strToHex(encMsg, len));
	toSend.append("\",\"publickey\":\"");
	toSend.append(client_pubkey);
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

/**
 * Public method to get balance.
 * @param addr is the account address
 * @return The balance
 */
std::string Blockchain::getBalance(char* addr)
{
	if(addr == "" || addr == NULL) return "Address is not available.";

	std::string url = IH_URL_GB;
	unsigned char* encMsg = new unsigned char[ENC_LENGTH];
	unsigned char* encMsgBin = new unsigned char[ENC_LENGTH];
	std::string content = "{\"address\":\"";
	content.append(addr);
	content.append("\"}");

	// Encrypt message
	int len = encryptAES(CLIENT_KEY, content, encMsg);

	std::string toSend = "{\"encryptedkey\": \"";
	toSend.append(base64_encode(m_encrypted_key, ENC_LENGTH) );
	toSend.append("\",\"encrypteddata\":\"");
	toSend.append(strToHex(encMsg, len));
	toSend.append("\",\"publickey\":\"");
	toSend.append(client_pubkey);
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

/**
 * Public method to unlock account at blockchain
 * @param addr is the user address to unlock.
 * @param pass is the user password.
 * @return true if ok
 */
bool Blockchain::unlockAccounts(char* addr, char* pass)
{
	if(strlen(addr) != VALID_ADDR_LEN || pass == "") return false;

	std::string url = IH_URL_UA;
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
	toSend.append(base64_encode(m_encrypted_key, ENC_LENGTH) );
	toSend.append("\",\"encrypteddata\":\"");
	toSend.append(strToHex(encMsg, len));
	toSend.append("\",\"publickey\":\"");
	toSend.append(client_pubkey);
	toSend.append("\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);
	std::cout << response << std::endl;

	return true;
}

/**
 * Public method to call addToVoter function from smart contract.
 * @param name is the voter's name.
 * @param id is the voter's id.
 * @param addr is the voter's address.
 * @return true if ok
 */
bool Blockchain::addToVoter(char* name, char* id, char* addr)
{
	if(strlen(addr) != VALID_ADDR_LEN || name == "" || id == "") return false;

	std::string url = IH_URL_SC_PARAM;
	
	std::string toSend = "{\"contractAddress\": \"";
	toSend.append(CONTRACT_ADDR);
	toSend.append("\", \"from\":\"");
	toSend.append(ADMIN_ADDR);
	toSend.append("\",\"method\":\"addToVoter(\'");
	toSend.append(name);
	toSend.append("\',\'");
	toSend.append(id);
	toSend.append("\',\'");
	toSend.append(addr);
	toSend.append("\')\", \"gasPrice\": \"200000\", \"gasLimit\": \"6000000\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);

	std::cout << response << std::endl;

	return true;
}

/**
 * Public method to call getAllVoters fro smart contract
 * @return true if ok
 */
bool Blockchain::getAllVoters()
{
	std::string url = IH_URL_SC;
	
	std::string toSend = "{\"contractAddress\": \"";
	toSend.append(CONTRACT_ADDR);
	toSend.append("\", \"from\":\"");
	toSend.append(ADMIN_ADDR);
	toSend.append("\",\"method\":\"getAllVoters()\",");
	toSend.append("\"gasPrice\": \"200000\", \"gasLimit\": \"6000000\"}");

	std::cout << toSend << std::endl;

	std::string response = postApiWithHeaders((char*) url.c_str(), toSend);

	std::cout << response << std::endl;

	return true;
}

/**
 * Private method to receive callback from post/get API.
 * @param contents pointer of response.
 * @param size is always 1.
 * @param nmemb is the size of the data.
 * @param userp the data received
 * @return total size of actual data received
 */
size_t Blockchain::writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

/**
 * Private method to send GET API.
 * @param url is the URL for GET API.
 * @return the GET response
 */
std::string Blockchain::getApi(char* url) 
{

	std::string readBuffer;

	curl_easy_setopt(m_curl, CURLOPT_URL, url);
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &readBuffer);
	m_res = curl_easy_perform(m_curl);

	return readBuffer;
}

/**
 * Private method to send GET API with header.
 * @param url is the URL for GET API.
 * @return the GET response
 */
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

/**
 * Private method to send POST API with header.
 * @param url is the URL for POST API.
 * @param postdata is the POST data.
 * @return the POST response.
 */
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

	std::string bal = Blockchain::GetInstance()->getBalance((char*)ADMIN_ADDR);
	
	if(stoi(bal) > 0) {
		Blockchain::GetInstance()->unlockAccounts((char*)ADMIN_ADDR, (char*)ADMIN_PASS);
		std::string addr = Blockchain::GetInstance()->createAccounts((char*) id.c_str());
		Blockchain::GetInstance()->addToVoter((char*)"Ammar456", (char*)"811225334455", (char*)addr.c_str());
		Blockchain::GetInstance()->getAllVoters();
	}	

	return 0;

}
#endif
