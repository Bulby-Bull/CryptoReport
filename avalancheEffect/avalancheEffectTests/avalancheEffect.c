//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve, 
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and 
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO 
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST
// NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE 
// UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST 
// DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE
// OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
// RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and 
// distributing the software and you assume all risks associated with its use, 
// including but not limited to the risks and costs of program errors, compliance 
// with applicable laws, damage to or loss of data, programs or equipment, and 
// the unavailability or interruption of operation. This software is not intended
// to be used in any situation where a failure could cause risk of injury or 
// damage to property. The software developed by NIST employees is not subject to
// copyright protection within the United States.
//

// disable deprecation for sprintf and fopen
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>

#include <assert.h>
#include <ctype.h>
#include "crypto_aead.h"
#include "api.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			8
#define MAX_ASSOCIATED_DATA_LENGTH		32



static int xor_hex(const unsigned char *s1, const unsigned char *s2, unsigned char *x3, unsigned long long len)
{
    for(int i = 0; i<len; i++)
    {
        unsigned char u1 = *s1++;
        unsigned char u2 = *s2++;
        *x3++ = u1^u2;
    }
    return 0;
}

unsigned int countSetBits(unsigned char *s1,unsigned long long len )
{
    unsigned int count = 0;
    unsigned char n;
    for(int i = 0; i<len; i++)
    {
    	n = *s1++;
	    while (n) {
	        count += n & 1;
	        n >>= 1;
	    }
	}
    return count;
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void modify_buffer(unsigned char *buffer,unsigned numByte, unsigned numModifiedByte);
void nonce_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

int main()
{
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		fprintf(stderr, "test vector generation failed with code %d\n", ret);
	}

	return ret;
}

int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char       key_modified[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char		nonce_modified[CRYPTO_NPUBBYTES];

	unsigned char      	pt[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned char		ctsave[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;
	
	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(pt, sizeof(pt));
	init_buffer(ad, sizeof(ad));

	for(int isPlaintext = 0; isPlaintext<=1;isPlaintext++){
	for(int nbByteModified=1;nbByteModified<=5;nbByteModified++){
		if(isPlaintext==0){
			sprintf(fileName, "BHANQUIN_AVALANCHE_EFFECT_NONCE_%d_%d_BITSMODIF_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8),nbByteModified);
		}else{
			sprintf(fileName, "BHANQUIN_AVALANCHE_EFFECT_KEY_%d_%d_BITSMODIF_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8),nbByteModified);
		}

	if ((fp = fopen(fileName, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
		return KAT_FILE_OPEN_ERROR;
	}
unsigned long long adlen = 0;
			unsigned long long mlen = MAX_MESSAGE_LENGTH;
			mlen2 = MAX_MESSAGE_LENGTH;
			fprintf(fp, "Count = %d\n", count++);

			fprint_bstr(fp, "Key = ", key, CRYPTO_KEYBYTES);

			fprint_bstr(fp, "Nonce = ", nonce, CRYPTO_NPUBBYTES);

			fprint_bstr(fp, "PT = ", pt, mlen);

			fprint_bstr(fp, "AD = ", ad, adlen);

			if ((func_ret = crypto_aead_encrypt(ctsave, &clen,pt, mlen, ad, adlen, NULL, nonce, key)) != 0) {
				fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
				ret_val = KAT_CRYPTO_FAILURE;
			}

			fprint_bstr(fp, "CTBase = ", ctsave, clen);
			unsigned char xorKey[CRYPTO_KEYBYTES];
			unsigned char xorNonce[CRYPTO_NPUBBYTES];
			unsigned char xorCT[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
			fprintf(fp, "\n");
	for (unsigned long long counterFive = 0; (counterFive < 5) ; counterFive++) {

	//	for (unsigned long long adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {
			if(isPlaintext==0){
			memcpy(nonce_modified, nonce, CRYPTO_NPUBBYTES);
			modify_buffer(nonce_modified,counterFive,nbByteModified);
			if ((func_ret = crypto_aead_encrypt(ct, &clen, pt, mlen, ad, adlen, NULL, nonce_modified, key)) != 0) {
                        fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
                        ret_val = KAT_CRYPTO_FAILURE;
                        break;
            }
			fprint_bstr(fp, "NONCE_Modif = ", nonce_modified, CRYPTO_NPUBBYTES);
            fprint_bstr(fp, "CT_Modif = ", ct, clen);
            xor_hex(nonce_modified,nonce,xorNonce,CRYPTO_NPUBBYTES);
            fprint_bstr(fp, "Both Nonce xored =" , xorNonce , CRYPTO_NPUBBYTES);
		}else{
			memcpy(key_modified, key, CRYPTO_KEYBYTES);
			modify_buffer(key_modified,counterFive,nbByteModified);
			if ((func_ret = crypto_aead_encrypt(ct, &clen, pt, mlen, ad, adlen, NULL, nonce, key_modified)) != 0) {
                        fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
                        ret_val = KAT_CRYPTO_FAILURE;
                        break;
            }
			fprint_bstr(fp, "KEY_Modif = ", key_modified, CRYPTO_KEYBYTES);
            fprint_bstr(fp, "CT_Modif = ", ct, clen);
            xor_hex(key_modified,key,xorKey,CRYPTO_KEYBYTES);
            fprint_bstr(fp, "Both key xored =" , xorKey , CRYPTO_KEYBYTES);
		}
			
            xor_hex(ctsave,ct,xorCT,clen);
            fprint_bstr(fp, "Both CT xored =" , xorCT , clen);
            fprintf(fp,"Bit modified = %d , percentage = %.2f%% \n" , countSetBits(xorCT,clen), (float)countSetBits(xorCT,clen) / (clen * 8) * 100 );
			fprintf(fp, "\n");
	}
}

	fclose(fp);
	}
	return ret_val;
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}


void modify_buffer(unsigned char *buffer,unsigned numByte, unsigned numModifiedByte){
	for(int i = 0;i<numModifiedByte;i++){
	buffer[numByte] ^= 1UL << i;
}
}

