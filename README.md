# Source
We can find the source of AES implementations at : https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption. 

# Configurations
All configurations are hardcorded in implementations. 
* Key= 01234567890123456789012345678901;
* IV = 0123456789012345;
* Additional data = Super additional data;
* Plaintext = available in file text corresponding to the size;

# Compilation
To use AES implementations you must install open-ssl library. For this you can execute this command: 
*sudo apt-get install libssl-dev*.
Then, you can compile applications with these commands : 
* for AES-GCM : *gcc -o gcm_impl.o gcm_impl.c -lcrypto*
* For AES-CCM : *gcc -o ccm_impl.o ccm_impl.c -lcrypto*
* For Saturnin-CTR-Cascade : *gcc -o saturnin_impl.o saturnin_impl.c -lcrypto*