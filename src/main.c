#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <tomcrypt.h>
#include <openssl/rand.h>


int main(){
    printf("Hello World\r\n");
    
    const char* celebrate = "Test String...";
    uint8_t len = strlen(celebrate);
    unsigned char encrypted_text[len];
    unsigned char unenc_text[len];

    //Register cipher
    register_cipher(&aes_desc); 

    //Start setting a CTR instance.
    unsigned char iv_buffer[16], key[32]; 
    if(RAND_bytes(iv_buffer, sizeof(iv_buffer)) == 0 || RAND_bytes(key, sizeof(key)) == 0){
        printf("...RC == 0...\r\n");
    }
    
    symmetric_CTR ctr_state;
    printf("%d\r\n", ctr_start(find_cipher("aes"), iv_buffer, key, sizeof(key), 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr_state));
    printf("key: %x, IV: %x\r\n", *key, *iv_buffer);

    printf("CTR_ENCRYPT: %d\r\n", ctr_encrypt((unsigned char*)celebrate, encrypted_text, len, &ctr_state));
    printf("%s\r\n", celebrate);
    printf("%x\r\n", encrypted_text);
    
    printf("Setting IV rc: %d\r\n", ctr_setiv(iv_buffer, sizeof(iv_buffer), &ctr_state)); 

    printf("\r\nCTR_DECRYPT: %d\r\n", ctr_decrypt(encrypted_text, unenc_text, len, &ctr_state));
    printf("%s\r\n", unenc_text);
    return 0;
}
