# Saturnin_AES_Comparison

# Source
We can find the source of AES implementations at : https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption. 

For Saturnin the source code is available at : https://project.inria.fr/saturnin/fr/.

# Configurations
All configurations are hardcorded in implementations. 
* Key= 01234567890123456789012345678901;
* IV = 0123456789012345;
* Additional data = Super additional data;
* Plaintext = 1KB directly hardcoded in the C code and can be expend.;

# Compilation
To use AES implementations you must install open-ssl library. For this you can execute this command
in the directory /AES_Saturn_Comparison/tests: 
*sudo apt-get install libssl-dev*.
Then, you can compile applications with these commands : 
* For AES-GCM : *gcc -o gcm_impl.o gcm_impl.c -lcrypto*
* For AES-CCM : *gcc -o ccm_impl.o ccm_impl.c -lcrypto*
  
To use Saturnin-CTR-Cascade, you must run this command in the directory "/AES_Saturn_Comparison/tests" where there are
saturnin_impl.c file : 
* For Saturnin-CTR-Cascade : *gcc -I . -I ../crypto_aead/saturninctrcascadev2/ref saturnin_impl.c ../crypto_aead/saturninctrcascadev2/ref/*.c

Execution for Saturnin with 1MB of plaintext can be take 5 min for encrypt and 5 to decrypt due to the 
loop to have 1000 results and a correct average. 