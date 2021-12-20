/* Libraries used:
 * NTL
 * OpenSSL
 * Terminal command using the 2 libraries:
 * g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm -L/usr/local/lib/ -lssl -lcrypto
 *
 * This is the c++ version of the examples.c
 */
#include <NTL/ZZ.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string>
#include <string.h>
#include <iomanip>
#include <stdio.h>
#include <cstring>
#include <iostream>

using namespace std;
using namespace NTL;

void sha_example()
{
  /* hash a string with sha256 */
  // need a more efficient way of converting string to char* (c equivalent?)
	string message = "this is a test message :D";
  char message_array[message.length() + 1];
  strcpy(message_array, message.c_str());

	unsigned char hash[32];
  SHA256((unsigned char*)message_array,message.length(),hash);
	for (size_t i = 0; i < 32; i++) {
		printf("%02x",hash[i]);
	}
	printf("\n");
}
/* demonstrates HMAC */
void hmac_example()
{
	string hmackey = "asdfasdfasdfasdfasdfasdf";
  char hmackey_array[hmackey.length() + 1];
  strcpy(hmackey_array, hmackey.c_str());

	unsigned char mac[64]; /* if using sha512 */
	memset(mac,0,64);
  string message = "this is a test message :D";
  char message_array[message.length() + 1];
  strcpy(message_array, message.c_str());
	HMAC(EVP_sha512(),hmackey_array,hmackey.length(),(unsigned char*)message_array,
			message.length(),mac,0);
	printf("hmac-512(\"%s\"):\n",message_array);
	for (size_t i = 0; i < 64; i++) {
		printf("%02x",mac[i]);
	}
	printf("\n");
}

/* demonstrates AES in counter mode */
void ctr_example()
{
	unsigned char aes_key[256];
	size_t i;
	// needs to be iv and key must be random(use NTL random)
	/* setup dummy (non-random) key and IV */
	for (i = 0; i < 256; i++) 
	{
		size_t rng = RandomBnd(93) + 33;
		aes_key[i] = rng;
		// cout << "Random #: " << key[i] << endl;
	};
	// cout << "Key: " << aes_key << endl;
	unsigned char iv[128];
	// generate 16 byte IV
	for (i = 0; i < 128; i++)
	{
		size_t rng = RandomBnd(93) + 33;
		iv[i] = rng;
		// cout << "Random #: " << iv[i] << endl;
	}
	// cout << "16 byte IV: " << iv << endl;
	/* NOTE: in general you need t compute the sizes of these
	 * buffers.  512 is an arbitrary value larger than what we
	 * will need for our short message. */
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	string message = "THIS IS A TEST FOR AES!";
  char message_array[message.length() + 1];
  strcpy(message_array, message.c_str());

	size_t len = message.length();
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,aes_key,iv))
		ERR_print_errors_fp(stderr);
	int nWritten; /* stores number of written bytes (size of ciphertext) */
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message_array,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctLen = nWritten;
	printf("ciphertext of length %i:\n",nWritten);
	for (i = 0; i < ctLen; i++) {
		printf("%02x",ct[i]);
	}
	printf("\n");
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work.  Also
	 * note that it is crucial to make sure IVs are not reused, though it
	 * Won't be an issue for our hybrid scheme as AES keys are only used
	 * once.  */
	/* wipe out plaintext to be sure it worked: */
	memset(pt,0,512);
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,aes_key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctLen))
		ERR_print_errors_fp(stderr);
	printf("decrypted %i bytes:\n%s\n",nWritten,pt);
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}

int main()
{
	// ZZ x;
	// x = RandomBits_ZZ(128);
	// cout << x << endl;
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	ctr_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// sha_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// hmac_example();
	return 0;
}
