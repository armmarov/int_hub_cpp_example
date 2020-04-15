#include <iostream>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sstream>

#include <algorithm>
#include <inttypes.h>
#include <vector>

#define AES_KEYLENGTH 256
#define ENC_LENGTH 128
#define CLIENT_KEY "a51f8cb2242b8009c6139e98379a5fab"
#define IV_VAL "0123456789012345"

RSA *client_public_key;
RSA *client_private_key;
RSA *server_public_key;

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
            ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
            char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

  return ret;
}

std::string decryptAES(unsigned char* key, unsigned char* enc_msg) 
{
	size_t len = strlen((char*)enc_msg);
	unsigned char aes_key[AES_KEYLENGTH];
	memset(aes_key, 0, AES_KEYLENGTH/8);
	strcpy((char*) aes_key, (char*)key);

	unsigned char iv[] = IV_VAL;

	const size_t encslength = ((len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char dec_out[len];
	memset(dec_out, 0, sizeof(dec_out));

	AES_KEY dec_key;
	AES_set_decrypt_key(aes_key, AES_KEYLENGTH, &dec_key);
	AES_cbc_encrypt(enc_msg, dec_out, encslength, &dec_key, iv, AES_DECRYPT);

	// Filter actual string
	std::stringstream ss;
	for(int i = 0; i < len; i++)
	{
		ss << dec_out[i];
		
	}
	std::string temp = ss.str();
	size_t idx_start = temp.find("\"");
	size_t idx_end = temp.substr(idx_start + 1, temp.length()).find("\"");

	return temp.substr(idx_start + 1, idx_end - idx_start);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encryptAES(std::string key, std::string msg, unsigned char* enc_msg) 
{
	/* Validation
	 * https://www.devglan.com/online-tools/aes-encryption-decryption
	 */

	EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;
	
	size_t inputslength = msg.length();
	unsigned char aes_input[inputslength];
	unsigned char aes_key[AES_KEYLENGTH];
	memset(aes_input, 0, inputslength/8);
	memset(aes_key, 0, AES_KEYLENGTH/8);
	strcpy((char*) aes_input, msg.c_str());
	strcpy((char*) aes_key, key.c_str());

	unsigned char *iv = (unsigned char *)IV_VAL;

	memset(enc_msg, 0, sizeof(enc_msg));

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, enc_msg, &len, aes_input, inputslength))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, enc_msg + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key) 
{	
    int result = RSA_public_encrypt(flen, from, to, key, RSA_PKCS1_OAEP_PADDING);
    return result;
}

int private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key) 
{
    int result = RSA_private_decrypt(flen, from, to, key, RSA_PKCS1_OAEP_PADDING);
    return result;
}

RSA * createRSA(unsigned char * key, bool isPublic)
{
	/* Validation
	 * https://www.devglan.com/online-tools/rsa-encryption-decryption
	 */

    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        std::cout << "Failed to create key BIO" << std::endl;
        return 0;
    }
    if(isPublic)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
 
    return rsa;
}

char * strToHex(unsigned char *str, int len){
  char *buffer = new char[len*2+1];
  char *pbuffer = buffer;
  for(int i = 0; i < len ; ++i ){
    sprintf(pbuffer, "%02X", str[i]);
    pbuffer += 2;
  }
  return buffer;
}

int charToInt(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument("Invalid input string");
}

void hexToBin(const char* src, char* target)
{
  while(*src && src[1])
  {
    *(target++) = charToInt(*src)*16 + charToInt(src[1]);
    src += 2;
  }
}