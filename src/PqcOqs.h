/**
  ******************************************************************************
  * @file           : PqcOqs
  * @brief          : Class PqcOqs define use PQC function 
  ******************************************************************************
  ******************************************************************************
  * Release History
  * branch name, working description, time
  * version_001: define add version  2025-08-11
  ******************************************************************************
  */

#ifndef __PQCOQS_HPP
#define __PQCOQS_HPP

#include <iostream>
#include <oqs/oqs.h>


// Debug print
#ifdef DEBUG
#define DBG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

class PqcOqs {
private:

public:

    /**
     * @brief Cleanup zero out key
     * @param ptr The start of the memory to zero out.
     * @param len The number of bytes to zero out.
     * @return
     */
    void clean_key(uint8_t *ptr, size_t len);

    /**
     * @brief Generate KEM key pair
     * @param public_key Public key buffer
     * @param private_key Private key buffer
     * @param alg_type algorithm type
     * @param public_key_max_buf Public key buffer max length
     * @param private_key_max_buf Private key buffer max length
     * @return Success 0, Fail -1
     */    
    int kem_create_keypair(uint8_t *public_key, uint8_t *private_key, int alg_type, int public_key_max_buf, int private_key_max_buf);

    /**
     * @brief KEM Key Encapsulate
     * @param ciphertext KEM capsulate data
     * @param shared_secret_e shared secret data
     * @param public_key public key
     * @param alg_type algorithm type
     * @param ciphertext_max_buf Ciphertext buffer max length
     * @param shared_secret_e_max_buf shared_secret_e buffer max length
     * @param public_key_max_buf Public key buffer max length
     * @return Success 0, Fail -1
     */      
    int kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret_e, const uint8_t *public_key, int alg_type,
         int ciphertext_max_buf, int shared_secret_max_buf, int public_key_max_buf);

    /**
     * @brief KEM Key Decapsulate
     * @param shared_secret_d shared secret data
     * @param ciphertext KEM capsulate data
     * @param private_key Private key buffer
     * @param alg_type algorithm type
     * @param shared_secret_e_max_buf shared_secret_e buffer max length
     * @param ciphertext_max_buf Ciphertext buffer max length
     * @param private_key_max_buf Private key buffer max length
     * @return Success 0, Fail -1
     */      
    int kem_decapsulate(uint8_t *shared_secret_d, const uint8_t *ciphertext, const uint8_t *private_key, int alg_type,
         int shared_secret_max_buf, int ciphertext_max_buf, int private_key_max_buf);

    /**
     * @brief Generate ML-DSA key pair
     * @param public_key Public key buffer
     * @param private_key Private key buffer
     * @param alg_type algorithm type
     * @param public_key_max_buf Public key buffer max length
     * @param private_key_max_buf Private key buffer max length
     * @return Success 0, Fail -1
     */    
    int mldsa_create_keypair(uint8_t *public_key, uint8_t *private_key, int alg_type, int public_key_max_buf, int private_key_max_buf);

    /**
     * @brief ML-DSA Sign 
     * @param signature Public key buffer
     * @param message Private key buffer
     * @param message_len algorithm type
     * @param alg_type algorithm type
     * @param private_key Public key buffer max length
     * @param private_key_max_buf Private key buffer max length
     * @return Success signed data length, Fail -1
     */    
    int mldsa_sign(uint8_t *signature, const uint8_t *message, size_t message_len, int alg_type, const uint8_t *private_key, int private_key_max_buf);

    /**
     * @brief ML-DSA Verify
     * @param signature signature message
     * @param signature_len signature message length
     * @param message plain message
     * @param message_len plain message length
     * @param alg_type algorithm type
     * @param public_key Public key buffer
     * @param public_key_max_buf Public key buffer max length
     * @return Success 0 Fail -1
     */    
    int mldsa_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, int alg_type, const uint8_t *public_key, int public_key_max_buf);


    



};

#endif /* __PQCOQS_HPP */