#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>

void handleErrors(void);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int main (void)
{

    /* Setup time */
    clock_t start, end;
    double cpu_time_used;

    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    /* Message to be encrypted */
    //1KB plaintext
    unsigned char *plaintext =
            (unsigned char *)"dkjfmqlskfdjmfjmlsdfjkjdkjfmdlkjjjjjgjj123456789dsfdsffSEZEGZGdqgsgqdqgggqgdsgdq qsdfqsfjmlkjsdjfmqsf dsfq fkdmlfmjdfjqlkdf lkqsdfjkmkflmdjmfkqk sdfjmsldkfjmkqsjdfmk qsdfjmskfjdmk sfd mqfjsdm fqdsmf  dsfqkmjsldfkjmsdjfjd ksfmdsflkdqmfdjfmqdslfjkm sdflkjsldkfjqsmfd qmsdjkfjdmlfj sdlfjkqmsdfkmqsdfjdslfkjksqmdfd fqsdfkjsdfmqdjfkmqd sfqlkdsjfkmds fjmqdfkm dkjfmqjkdmqdkfjmqjfmdlkjqm fksjdkfmd qfkjdmjfqksdjfmkqsjdmfjdqlfjkqsdjflkqdsj fqmsdljfkdqjfdljflsmfjlkdjfmjqldsjfmldsfjqjdk fdksmlfjdklfjqdmslfjm dkjfmqlskfdjmfjmlsdfjkjdkjfmdlkjjjjjgjj123456789dsfdsffSEZEGZGdqgsgqdqgggqgdsgdq qsdfqsfjmlkjsdjfmqsf dsfq fkdmlfmjdfjqlkdf lkqsdfjkmkflmdjmfkqk sdfjmsldkfjmkqsjdfmk qsdfjmskfjdmk sfd mqfjsdm fqdsmf  dsfqkmjsldfkjmsdjfjd ksfmdsflkdqmfdjfmqdslfjkm sdflkjsldkfjqsmfd qmsdjkfjdmlfj sdlfjkqmsdfkmqsdfjdslfkjksqmdfd fqsdfkjsdfmqdjfkmqd sfqlkdsjfkmds fjmqdfkm dkjfmqjkdmqdkfjmqjfmdlkjqm fksjdkfmd qfkjdmjfqksdjfmkqsjdmfjdqlfjkqsdjflkqdsj fqmsdljfkdqjfdljflsmfjlkdjfmjqldsjfmldsfjqjdk fdksmlfjdklfjqdmslf02";

    /* Additional data */
    unsigned char *additional =
            (unsigned char *)"Super additional data";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[1024];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[1024];

    /* Buffer for the tag */
    unsigned char tag[16];

    double timecache;

    int decryptedtext_len, ciphertext_len;

//////ENCRYPTION PART//////

//Loop for the nb of time to encrypt (*10 for 10 KB and *1000 for 1MB)
    for(int j = 0 ; j < 1000 ; j++){
        //Loop to have an average result
        for(int i = 0 ; i < 1000 ; i++){

            /* Start clock for encryption*/
            start = clock();

            /* Encrypt the plaintext */
            ciphertext_len = gcm_encrypt(plaintext, strlen ((char *)plaintext),
                                         additional, strlen ((char *)additional),
                                         key,
                                         iv, iv_len,
                                         ciphertext, tag);

            /* Show time taken */
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            timecache = timecache + cpu_time_used*1000;
        }
    }

    printf("Average time to cipher : %f",  timecache/1000);
    timecache = 0;

//////DECRYPTION PART//////

    for(int j = 0 ; j < 1000 ; j++){
        for(int i = 0 ; i < 1000 ; i++){

            /* Start clock for decryption*/
            start = clock();

            /* Decrypt the ciphertext */
            decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                            additional, strlen ((char *)additional),
                                            tag,
                                            key, iv, iv_len,
                                            decryptedtext);

            if (decryptedtext_len >= 0) {
                /* Add a NULL terminator. We are expecting printable text */
                decryptedtext[decryptedtext_len] = '\0';

            } else {
                printf("Decryption failed\n");
            }

            /* Show time taken */
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            timecache = timecache + cpu_time_used*1000;
        }
    }

    printf("Average time to decipher : %f",  timecache/1000);
    timecache = 0;

    /* Decrypt the ciphertext with modified tag */
    decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

    } else {
        printf("Decryption failed\n");
    }

    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}