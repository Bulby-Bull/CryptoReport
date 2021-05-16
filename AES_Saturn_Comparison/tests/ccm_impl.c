#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>

void handleErrors(void);
int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag);
int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
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

    int decryptedtext_len, ciphertext_len;

    double timecache;

//////ENCRYPTION PART//////

//Loop for the nb of time to encrypt (*10 for 10 KB and *1000 for 1MB)
    for(int j = 0 ; j < 1000 ; j++){
        //Loop to have an average result
        for(int i = 0 ; i < 1000 ; i++){

            /* Start clock for encryption*/
            start = clock();

            /* Encrypt the plaintext */
            ciphertext_len = ccm_encrypt(plaintext, strlen ((char *)plaintext),
                                         additional, strlen ((char *)additional),
                                         key,
                                         iv,
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
            decryptedtext_len = ccm_decrypt(ciphertext, ciphertext_len,
                                            additional, strlen ((char *)additional),
                                            tag,
                                            key, iv,
                                            decryptedtext);
            if (decryptedtext_len >= 0) {
                /* Add a NULL terminator. We are expecting printable text */
                decryptedtext[decryptedtext_len] = '\0';

                /* Show time taken */
                end = clock();
                cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
                timecache = timecache + cpu_time_used*1000;
                //printf("\n");
            } else {
                printf("Decryption failed\n");
            }

        }
    }

    printf("Average time to decipher : %f",  timecache/1000);
    timecache = 0;

    /* Start clock for decryption*/
    start = clock();

    /* Decrypt the ciphertext with modified tag */
    decryptedtext_len = ccm_decrypt(ciphertext, ciphertext_len,
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show time taken */
        end = clock();
        cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        //printf("Time to decrypt and check the tag in ms: %f", cpu_time_used*1000);

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


int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
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
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example.
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
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
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

    /* Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set expected tag value. */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();


    /* Provide the total ciphertext length */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}