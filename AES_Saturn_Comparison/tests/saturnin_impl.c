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


#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crypto_aead.h"
#include "api.h"


#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32

void do_Saturnin_Impl();

int main()
{
	do_Saturnin_Impl();

	return 0;
}

void do_Saturnin_Impl()
{

	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[1024];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[1024 + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2;
	unsigned long long  adlen;
	
	
	/* Setup time */
	clock_t start, end;
    	double cpu_time_used;

	double timecache;

	memcpy(nonce, "0123456789012345", 16);//Setup nonce
	memcpy(key, "01234567890123456789012345678901", 32);//Setup key
	memcpy(ad, "Super additional data", 32);//Setup additional data
	
	//1KB plaintext
	unsigned char *plaint =
        (unsigned char *)"dkjfmqlskfdjmfjmlsdfjkjdkjfmdlkjjjjjgjj123456789dsfdsffSEZEGZGdqgsgqdqgggqgdsgdq qsdfqsfjmlkjsdjfmqsf dsfq fkdmlfmjdfjqlkdf lkqsdfjkmkflmdjmfkqk sdfjmsldkfjmkqsjdfmk qsdfjmskfjdmk sfd mqfjsdm fqdsmf  dsfqkmjsldfkjmsdjfjd ksfmdsflkdqmfdjfmqdslfjkm sdflkjsldkfjqsmfd qmsdjkfjdmlfj sdlfjkqmsdfkmqsdfjdslfkjksqmdfd fqsdfkjsdfmqdjfkmqd sfqlkdsjfkmds fjmqdfkm dkjfmqjkdmqdkfjmqjfmdlkjqm fksjdkfmd qfkjdmjfqksdjfmkqsjdmfjdqlfjkqsdjflkqdsj fqmsdljfkdqjfdljflsmfjlkdjfmjqldsjfmldsfjqjdk fdksmlfjdklfjqdmslfjm dkjfmqlskfdjmfjmlsdfjkjdkjfmdlkjjjjjgjj123456789dsfdsffSEZEGZGdqgsgqdqgggqgdsgdq qsdfqsfjmlkjsdjfmqsf dsfq fkdmlfmjdfjqlkdf lkqsdfjkmkflmdjmfkqk sdfjmsldkfjmkqsjdfmk qsdfjmskfjdmk sfd mqfjsdm fqdsmf  dsfqkmjsldfkjmsdjfjd ksfmdsflkdqmfdjfmqdslfjkm sdflkjsldkfjqsmfd qmsdjkfjdmlfj sdlfjkqmsdfkmqsdfjdslfkjksqmdfd fqsdfkjsdfmqdjfkmqd sfqlkdsjfkmds fjmqdfkm dkjfmqjkdmqdkfjmqjfmdlkjqm fksjdkfmd qfkjdmjfqksdjfmkqsjdmfjdqlfjkqsdjflkqdsj fqmsdljfkdqjfdljflsmfjlkdjfmjqldsjfmldsfjqjdk fdksmlfjdklfjqdmslf02";
	memcpy(msg, plaint, 1024);
	mlen2 = 1024;
	adlen = 32;
	
	//////ENCRYPTION PART//////
	
	//Loop for the nb of time to encrypt (*10 for 10 KB and *1000 for 1MB)
	for(int j = 0 ; j < 1000 ; j++){
	//Loop to have an average result
		for(int i = 0 ; i < 1000 ; i++){
			/* Start clock for encryption*/
			start = clock();
			
			crypto_aead_encrypt(ct, &clen, msg, mlen2, ad, adlen, NULL, nonce, key);
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			timecache = timecache + cpu_time_used*1000;
		}
	}
	
	printf("Average time to cipher : %f \n",  timecache/1000);
	
	//////DECRYPTION PART//////
	
	timecache = 0;
	for(int j = 0 ; j < 1000 ; j++){
		for(int i = 0 ; i < 1000 ; i++){
			/* Start clock for decryption*/
			start = clock();
			
			crypto_aead_decrypt(msg, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);

			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			timecache = timecache + cpu_time_used*1000;
		}
	}
	printf("Average time to de decipher : %f \n",  timecache/1000);
	timecache = 0;
	
}



