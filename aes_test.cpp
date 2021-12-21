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

/* demonstrates HMAC */
// HMAC(IV|C)
void hmac(unsigned char* ct, int nWritten)
{
	string hmackey = "asdfasdfasdfasdfasdfasdf";
	char hmackey_array[hmackey.length() + 1];
	strcpy(hmackey_array, hmackey.c_str());

	unsigned char mac[64]; /* if using sha512 */
	memset(mac,0,64);
	HMAC(EVP_sha512(),hmackey_array,hmackey.length(),ct,
			nWritten,mac,0);
	printf("hmac-512(\"%s\"):\n",ct);
	for (size_t i = 0; i < 64; i++) {
		printf("%02x",mac[i]);
	}
	printf("\n");
}

/* demonstrates AES in counter mode encryption*/
int aes_encrypt(string message, unsigned char* aes_key, unsigned char* iv, unsigned char* ct,unsigned char* pt)
{
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
	for (size_t i = 0; i < ctLen; i++) {
		 printf("%02x",ct[i]);
	}
	cout << "\nCiphertext: " << ct << endl;
	printf("\n");
	// cout << "OG nWritten: " <<  nWritten << endl;
	return nWritten;

}
/* demonstrates AES in counter mode decryption*/
void aes_decrypt(unsigned char* aes_key, unsigned char* iv, unsigned char* ct,unsigned char* pt, int nWritten){
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work.  Also
	 * note that it is crucial to make sure IVs are not reused, though it
	 * Won't be an issue for our hybrid scheme as AES keys are only used
	 * once.  */
	/* wipe out plaintext to be sure it worked: */
	memset(pt,0,512);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,aes_key,iv))
		ERR_print_errors_fp(stderr);
	size_t ctLen = nWritten;
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctLen))
		ERR_print_errors_fp(stderr);
	printf("decrypted %i bytes:\n%s\n",nWritten,pt);
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}


int main()
{
	unsigned char aes_key[32]; // aes_key is 32 bytes
	size_t i;
	// needs to be iv and key must be random(use NTL random)
	for (i = 0; i < 32; i++)
	{
		size_t rng = RandomBnd(93) + 33; // From ASCII table, usable chars are from dec 33 - 126
		aes_key[i] = rng;
		// cout << aes_key[i];
	};
	// cout << "Key: " << aes_key << endl;
	unsigned char iv[16];
	// generate 16 byte IV
	for (i = 0; i < 16; i++)
	{
		size_t rng = RandomBnd(93) + 33;
		iv[i] = rng;
		// cout <<  iv[i];
	}
	// cout << "16 byte IV: " << iv << endl;
	/* NOTE: in general you need to compute the sizes of these
	 * buffers.  512 is an arbitrary value larger than what we
	 * will need for our short message. */
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	string message = "THIS IS A TEST FOR AES!";

	int nWritten = aes_encrypt(message, aes_key, iv, ct, pt);
	// cout << "nWritten: " <<  nWritten << endl;
	// aes_decrypt(aes_key, iv, ct, pt, nWritten); // Test aes_ecrypt works

	hmac(ct, nWritten);

	return 0;
}
