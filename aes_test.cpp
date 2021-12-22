/* Libraries used:
 * NTL
 * OpenSSL
 * Terminal command using the 2 libraries:
 * g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm -L/usr/local/lib/ -lssl -lcrypto
 *
 * g++ -g -O2 -std=c++11 foo.cpp -o foo -lssl -lcrypto -lntl -pthread -lgmp
 *
 * This is the c++ version of the examples.c
 */
#include <NTL/ZZ.h>
#include <NTL/ZZ_pX.h>
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
#include <fstream>

#define SHA256_CBLOCK 64
#define SHA256_DIGEST_LENGTH 32

using namespace std;
using namespace NTL;

/* storage for parameters: 
 * need these parameters for El Gamal*/
ZZ q,p,g;
ZZ ZZ_a; // secret key

/* We will be using the same readParams() provided to us from ntl-examples.cpp
 * Values are placed as before: q, p, g (in this order)
 * Values are stored in the file ./params-q-p-g
 * NOTE: Currently, the numbers are written in base 10
 *
 * Of course, we also just store the numbers in this file as well for ease
 * of testing
 * */

int readParams()
{
	ifstream fin("params-q-p-g");
	if (!fin.good()) {
		fprintf(stderr, "couldn't open parameter file.\n");
		return 1;
	}

	/* NOTE: q,p,g have been declared above at global scope*/

	//fin >> q >> p >> g;
	p = 23;
	q = 2;
	g = 20;
	fin.close();

	/* Let's perform a quick sanity check: are values which are
	 * suppoed to be prime actuall so?  Does q in fact divide
	 * the order of the multiplicative group mod p? */
	if (!ProbPrime(q)) {
		fprintf(stderr, "q not prime!\n");
		return -1;
	}
	if (!ProbPrime(p)) {
                fprintf(stderr, "p not prime!\n");
                return -1;
        }
        if ((p-1)%q != 0) {
                fprintf(stderr, "q does not divde p-1!\n");
                return -1;
        }
	if ((p-1)%(q*q) == 0) {
                fprintf(stderr, "q^2 divides p-1!\n");
                return -1;
        }
        /* lastly, let's check on the generator: */
        if (PowerMod(g,(p-1)/q,p) == 1) {
                fprintf(stderr, "g does not generate subgroup of size q!\n");
                return -1;
        }
	/* NOTE: we can also set the modulus for the ZZ_p datatypes.
         * This way you never have to perform any explicit reductions
         * when doing arithmetic, e.g., X*Y means X*Y % p for X,Y of
         * type ZZ_p. */
        ZZ_p::init(p);
        /* NOTE: for secret sharing, you could also use this, but you
         * will likely want to use parameter q instead. */
        return 0;
}


/* Use for initialization of NTL's internal RNG.
void initNTLRandom()
{
        FILE* frand = fopen("/dev/urandom","rb");
        unsigned char seed[32];
        fread(seed,1,32,frand);
        fclose(frand);
        SetSeed(seed,32);
}*/

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

unsigned int el_gamal_encrypt(ZZ ZZ_x, ZZ ZZ_b)
{
	cout << "EL GAMAL ENCRYPTING ... " << endl;

	// Need to generate secret key random a. 
	// SK = a in {1, ..., p-1}
	// Need to generate public key
	// PK = A = g^a
	
	// Generate random a
	
	unsigned int p_convert;
	p_convert = conv<uint>(p);
	cout << "p converted = " << p_convert << endl;
	ZZ_a = conv<ZZ>(RandomBnd(p_convert));


	// Generate Public Key
	ZZ ZZ_A;
	ZZ_A = power(g, conv<uint>(ZZ_a)) % p;

	// Now we encrypt, E_pk(x) = (B, s * x)
	// Where s is the shared secret
	
	// Generate the shared secret
	
	ZZ ZZ_s;
	ZZ_s = power(ZZ_A, conv<uint>(ZZ_b)) % p;
	ZZ_s = ZZ_s * ZZ_x;

	return conv<uint>(ZZ_s);
}

unsigned int el_gamal_decrypt(unsigned int h, ZZ ZZ_B) 
{
	cout << "EL GAMAL DECRYPTING ... " << endl; 
	unsigned int decrypted_x;
	ZZ ZZ_s;
	ZZ_s = power(ZZ_B, conv<uint>(ZZ_a));

	decrypted_x = h * ((1 / conv<uint>(ZZ_s)) % conv<uint>(p));	
	return decrypted_x;
}


// This is just hash function SHA-256 on value x
// Courtesy of Chromium-boringssl-docs on SHA-256
int h(ZZ ZZ_x){

	/* hash: */
	cout << "Size of x = " << sizeof(ZZ_x) << endl;

	size_t len = sizeof(ZZ_x);
	uint8_t out[SHA256_DIGEST_LENGTH];

	OPENSSL_EXPORT int SHA256_Init(SHA256_CTX *sha);
//		ERR_print_errors_fp(stderr);
	OPENSSL_EXPORT int SHA256_Update(SHA256_CTX *sha, const void *ZZ_x, size_t len);
//		ERR_print_errors_fp(stderr);
	OPENSSL_EXPORT int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha);
	OPENSSL_EXPORT uint8_t *SHA256(const uint8_t *ZZ_x, size_t len, uint8_t out[SHA256_DIGEST_LENGTH]);

	cout << "H(x) = " << out[SHA256_DIGEST_LENGTH] << endl;


	return 0;
}

int main()
{
	// Need to generate random value: x
	// for El Gamal and Hash function, SHA-256

	readParams();

	ZZ ZZ_x;
	ZZ_x = RandomBnd(10000000);
	
	cout << "Random number, x: " << ZZ_x << endl;
	cout << "q = " << q << endl;
	cout << "p = " << p << endl;
	cout << "g = " << g << endl;
	
	// El Gamal using Public Key Encryption

	// Generate random b, we need b later for decryption

	unsigned int p_convert = conv<uint>(p);
	cout << "p converted = " << p_convert << endl;
	ZZ ZZ_b = conv<ZZ>(RandomBnd(p_convert));
	
	// Generate B, using b.
	// May run out of memory here!
	ZZ ZZ_B = power(g, conv<uint>(ZZ_b)) % p;
	
	unsigned int E_Pk_x;
	E_Pk_x = el_gamal_encrypt(ZZ_x,ZZ_b);

	cout << "E_Pk_x:" << endl;
        cout << "B = " << ZZ_B << endl;
	cout << "s = " << E_Pk_x << endl;	

	unsigned int decrypt_x;
	decrypt_x = el_gamal_decrypt(E_Pk_x, ZZ_B);
	cout << "Decrpyted x = " << decrypt_x << endl;

	// SHA-256 hash of x
	h(ZZ_x);

	unsigned char aes_key[32]; // aes_key is 32 bytes
	// needs to be iv and key must be random(use NTL random)
	size_t i;
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
