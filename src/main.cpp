#include "main.h"
#include "Util.h"
#include "Define.h"
#include "ConfigRead.h"
#include "PqcOqs.h"
#include "../lib/json/json.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <oqs/oqs.h>
#include <string>
#include <cstring>
#include <dlfcn.h> // library load
#include <stdlib.h>
#include <stdbool.h>

Util util;
ConfigRead configread;
PqcOqs pqcoqs;

void ml_dsa_cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}

// Example stack
OQS_STATUS mldsa_test_stack(){

    // key buffer define
	uint8_t public_key[OQS_SIG_ml_dsa_65_length_public_key];
	uint8_t secret_key[OQS_SIG_ml_dsa_65_length_secret_key];
	uint8_t message[MESSAGE_LEN];
	size_t message_len = MESSAGE_LEN;
	uint8_t signature[OQS_SIG_ml_dsa_65_length_signature];
	size_t signature_len;

    // plain text
    OQS_randombytes(message, message_len);

    
    // create key pair
    printf("ML-DSA KEY Create: \n");
    OQS_STATUS rc = OQS_SIG_ml_dsa_65_keypair(public_key, secret_key);
    if(rc != OQS_SUCCESS){
        fprintf(stderr, "ERROR: OQS_SIG_ml_dsa_65_keypair failed!\n");
        ml_dsa_cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return rc;
    }

    // printf ml-dsa key
    printf("PUBLIC KEY: \n");
    for(int i=0; i < OQS_SIG_ml_dsa_65_length_public_key; i++){
        printf("%02x", public_key[i]);
    }
    printf("\n");

    // printf ml-dsa key
    printf("PRIVATE KEY: \n");
    for(int i=0; i < OQS_SIG_ml_dsa_65_length_secret_key; i++){
        printf("%02x", secret_key[i]);
    }
    printf("\n");

    // ML-DSA Sign
    printf("ML-DSA Sign: \n");
    rc = OQS_SIG_ml_dsa_65_sign(signature, &signature_len, message, message_len, secret_key);
    if(rc != OQS_SUCCESS){
		fprintf(stderr, "ERROR: OQS_SIG_ml_dsa_65_sign failed!\n");
		ml_dsa_cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return rc;
    }

    // print sign value
    printf("signature: \n");
    for(size_t i=0; i < signature_len; i++){
        printf("%02x", signature[i]);
    }
    printf("\n");


    // ML-DSA Verify 
    printf("ML-DSA Verify: \n");
    rc = OQS_SIG_ml_dsa_65_verify(message, message_len, signature, signature_len, public_key);
    if(rc != OQS_SUCCESS){
		fprintf(stderr, "ERROR: OQS_SIG_ml_dsa_65_verify failed!\n");
		ml_dsa_cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
		return rc;
    }

    printf("verify success \n");

	printf("[example_stack] OQS_SIG_ml_dsa_65 operations completed.\n");
	ml_dsa_cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
	return rc;
}


int main() {
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);

    
    OQS_init(); // Init

    // KEM key Capsulate

    // 1. generate KEM key pair
    uint8_t public_key[OQS_KEM_ml_kem_512_length_public_key]= {0};
    uint8_t private_key[OQS_KEM_ml_kem_512_length_secret_key]= {0};

    int status = pqcoqs.kem_create_keypair(public_key, private_key, KEM_512, 
        OQS_KEM_ml_kem_512_length_public_key, OQS_KEM_ml_kem_512_length_secret_key);

    if(status == SUCCESS){
        // printf kem key
        printf("PUBLIC KEY: \n");
        for(int i=0; i < OQS_KEM_ml_kem_512_length_public_key; i++){
            printf("%02x", public_key[i]);
        }
        printf("\n");

        // printf kem key
        printf("PRIVATE KEY: \n");
        for(int i=0; i < OQS_KEM_ml_kem_512_length_secret_key; i++){
            printf("%02x", private_key[i]);
        }
        printf("\n");
    }

    // 2. KEM key encapsulate
	uint8_t ciphertext[OQS_KEM_ml_kem_512_length_ciphertext]= {0};
	uint8_t shared_secret_e[OQS_KEM_ml_kem_512_length_shared_secret]= {0};

    status = pqcoqs.kem_encapsulate(ciphertext, shared_secret_e, public_key, KEM_512,
        OQS_KEM_ml_kem_512_length_ciphertext, OQS_KEM_ml_kem_512_length_shared_secret, OQS_KEM_ml_kem_512_length_public_key);
    
    if(status == SUCCESS){
        printf("shared_secret_e: \n");
        for(int i=0; i < OQS_KEM_ml_kem_512_length_shared_secret; i++){
            printf("%02x", shared_secret_e[i]);
        }
        printf("\n");

        printf("ciphertext: \n");
        for(int i=0; i < OQS_KEM_ml_kem_512_length_ciphertext; i++){
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
    }

    // 3. KEM key decapsulate
    uint8_t shared_secret_d[OQS_KEM_ml_kem_512_length_shared_secret];

    status = pqcoqs.kem_decapsulate(shared_secret_d, ciphertext, private_key, KEM_512,
        OQS_KEM_ml_kem_512_length_shared_secret, OQS_KEM_ml_kem_512_length_ciphertext, OQS_KEM_ml_kem_512_length_secret_key);

    if(status == SUCCESS){
        printf("shared_secret_d: \n");
        for(int i=0; i < OQS_KEM_ml_kem_512_length_shared_secret; i++){
            printf("%02x", shared_secret_d[i]);
        }
        printf("\n");
    }

    // 4. clean key
    pqcoqs.clean_key(public_key, OQS_KEM_ml_kem_512_length_public_key);
    pqcoqs.clean_key(private_key, OQS_KEM_ml_kem_512_length_secret_key);
    pqcoqs.clean_key(ciphertext, OQS_KEM_ml_kem_512_length_ciphertext);
    pqcoqs.clean_key(shared_secret_e, OQS_KEM_ml_kem_512_length_shared_secret);
    pqcoqs.clean_key(shared_secret_d, OQS_KEM_ml_kem_512_length_shared_secret);

    // ML-DSA Sign, Verify

    // 5. make plain text to random data
	uint8_t message[MESSAGE_LEN];
	size_t message_len = MESSAGE_LEN;
    OQS_randombytes(message, message_len);

    // 6. Create ML-DSA Key 
	uint8_t pub_key[OQS_SIG_ml_dsa_65_length_public_key];
	uint8_t secret_key[OQS_SIG_ml_dsa_65_length_secret_key];

    status = pqcoqs.mldsa_create_keypair(pub_key, secret_key, ML_DSA_65, OQS_SIG_ml_dsa_65_length_public_key, OQS_SIG_ml_dsa_65_length_secret_key);
    if(status != OQS_SUCCESS){
        printf("ERROR: OQS_SIG_ml_dsa_65_keypair failed!\n");
    }

    // printf ml-dsa key
    printf("PUBLIC KEY: \n");
    for(int i=0; i < OQS_SIG_ml_dsa_65_length_public_key; i++){
        printf("%02x", pub_key[i]);
    }
    printf("\n");

    // printf ml-dsa key
    printf("PRIVATE KEY: \n");
    for(int i=0; i < OQS_SIG_ml_dsa_65_length_secret_key; i++){
        printf("%02x", secret_key[i]);
    }
    printf("\n");

    // 7. ML-DSA Sign
	uint8_t signature[OQS_SIG_ml_dsa_65_length_signature];

    int sign_len = pqcoqs.mldsa_sign(signature, message, message_len, ML_DSA_65, secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
    if(sign_len <= 0){
        printf("ERROR: Sign fail\n");
    }
    else {
        // print sign value
        printf("signature: \n");
        for(int i=0; i < sign_len; i++){
            printf("%02x", signature[i]);
        }
        printf("\n");
    }

    // 8. ML-DSA Verify
    status = pqcoqs.mldsa_verify(signature, sign_len, message, message_len, ML_DSA_65, pub_key, OQS_SIG_ml_dsa_65_length_public_key);
    if(status == SUCCESS){
        printf("Verify Success \n");
    } else {
        printf("ERROR: Verify Fail\n");
    }

    // 9. Clean Key
    pqcoqs.clean_key(pub_key, OQS_SIG_ml_dsa_65_length_public_key);
    pqcoqs.clean_key(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
    pqcoqs.clean_key(message, message_len);
    pqcoqs.clean_key(signature, sign_len);




    OQS_destroy(); // clear
    return 0;
}