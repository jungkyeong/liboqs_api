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

#include "PqcOqs.h"
#include "Define.h"

/**
 * @brief Cleanup zero out key
 * @param ptr The start of the memory to zero out.
 * @param len The number of bytes to zero out.
 * @return
 */
void PqcOqs::clean_key(uint8_t *ptr, size_t len){
	OQS_MEM_cleanse(ptr, len);
}

/**
 * @brief Generate KEM key pair
 * @param public_key Public key buffer
 * @param private_key Private key buffer
 * @param alg_type algorithm type
 * @param public_key_max_buf Public key buffer max length
 * @param private_key_max_buf Private key buffer max length
 * @return Success 0, Fail -1
 */    
int PqcOqs::kem_create_keypair(uint8_t *public_key, uint8_t *private_key, int alg_type, int public_key_max_buf, int private_key_max_buf){

    DBG_PRINT("KEM KEY Create \n");

    // Buffer length check
    if(alg_type == KEM_512){
        if(public_key_max_buf < OQS_KEM_ml_kem_512_length_public_key || private_key_max_buf < OQS_KEM_ml_kem_512_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_768){
        if(public_key_max_buf < OQS_KEM_ml_kem_768_length_public_key || private_key_max_buf < OQS_KEM_ml_kem_768_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_1024){
        if(public_key_max_buf < OQS_KEM_ml_kem_1024_length_public_key || private_key_max_buf < OQS_KEM_ml_kem_1024_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }

    // Key Generate
    OQS_STATUS rc;
    if(alg_type == KEM_512){
        rc = OQS_KEM_ml_kem_512_keypair(public_key, private_key);
    }
    else if(alg_type == KEM_768){
        rc = OQS_KEM_ml_kem_768_keypair(public_key, private_key);
    }
    else if(alg_type == KEM_1024){
        rc = OQS_KEM_ml_kem_1024_keypair(public_key, private_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("KEM Key Generate fail \n");
        return FAIL;
    }
    DBG_PRINT("KEM Key Generate Success \n");
    return SUCCESS;
}

/**
 * @brief KEM Key Encapsulate
 * @param ciphertext KEM capsulate data
 * @param shared_secret_e shared secret data
 * @param public_key public key
 * @param alg_type algorithm type
 * @param ciphertext_max_buf Ciphertext buffer max length
 * @param shared_secret_max_buf shared_secret_e buffer max length
 * @param public_key_max_buf Public key buffer max length
 * @return Success 0, Fail -1
 */    
int PqcOqs::kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret_e, const uint8_t *public_key, int alg_type,
    int ciphertext_max_buf, int shared_secret_max_buf, int public_key_max_buf){

    DBG_PRINT("KEM KEY Encapsulate \n");

    // Buffer length check
    if(alg_type == KEM_512){
        if(public_key_max_buf < OQS_KEM_ml_kem_512_length_public_key || ciphertext_max_buf < OQS_KEM_ml_kem_512_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_768_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_768){
        if(public_key_max_buf < OQS_KEM_ml_kem_768_length_public_key || ciphertext_max_buf < OQS_KEM_ml_kem_768_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_768_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_1024){
        if(public_key_max_buf < OQS_KEM_ml_kem_1024_length_public_key || ciphertext_max_buf < OQS_KEM_ml_kem_1024_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_1024_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }
    // Key Encapsulate
    OQS_STATUS rc;
    if(alg_type == KEM_512){
        rc = OQS_KEM_ml_kem_512_encaps(ciphertext, shared_secret_e, public_key);
    }
    else if(alg_type == KEM_768){
        rc = OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret_e, public_key);
    }
    else if(alg_type == KEM_1024){
        rc = OQS_KEM_ml_kem_1024_encaps(ciphertext, shared_secret_e, public_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("KEM Key Encapsulate fail \n");
        return FAIL;
    }
    DBG_PRINT("KEM Key Encapsulate Success \n");
    return SUCCESS;
}

/**
 * @brief KEM Key Decapsulate
 * @param shared_secret_d shared secret data
 * @param ciphertext KEM capsulate data
 * @param private_key Private key buffer
 * @param alg_type algorithm type
 * @param shared_secret_max_buf shared_secret_e buffer max length
 * @param ciphertext_max_buf Ciphertext buffer max length
 * @param private_key_max_buf Private key buffer max length
 * @return Success 0, Fail -1
 */      
int PqcOqs::kem_decapsulate(uint8_t *shared_secret_d, const uint8_t *ciphertext, const uint8_t *private_key, int alg_type,
    int shared_secret_max_buf, int ciphertext_max_buf, int private_key_max_buf){

    DBG_PRINT("KEM KEY Decapsulate \n");

    // Buffer length check
    if(alg_type == KEM_512){
        if(private_key_max_buf < OQS_KEM_ml_kem_512_length_secret_key || ciphertext_max_buf < OQS_KEM_ml_kem_512_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_768_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_768){
        if(private_key_max_buf < OQS_KEM_ml_kem_768_length_secret_key || ciphertext_max_buf < OQS_KEM_ml_kem_768_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_768_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == KEM_1024){
        if(private_key_max_buf < OQS_KEM_ml_kem_1024_length_secret_key || ciphertext_max_buf < OQS_KEM_ml_kem_1024_length_ciphertext
        || shared_secret_max_buf < OQS_KEM_ml_kem_1024_length_shared_secret){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }
    // Key Decapsulate
    OQS_STATUS rc;
    if(alg_type == KEM_512){
        rc = OQS_KEM_ml_kem_512_decaps(shared_secret_d, ciphertext, private_key);
    }
    else if(alg_type == KEM_768){
        rc = OQS_KEM_ml_kem_768_decaps(shared_secret_d, ciphertext, private_key);
    }
    else if(alg_type == KEM_1024){
        rc = OQS_KEM_ml_kem_1024_decaps(shared_secret_d, ciphertext, private_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("KEM Key Decapsulate fail \n");
        return FAIL;
    }
    DBG_PRINT("KEM Key Decapsulate Success \n");
    return SUCCESS;
}

/**
 * @brief Generate ML-DSA key pair
 * @param public_key Public key buffer
 * @param private_key Private key buffer
 * @param alg_type algorithm type
 * @param public_key_max_buf Public key buffer max length
 * @param private_key_max_buf Private key buffer max length
 * @return Success 0, Fail -1
 */    
int PqcOqs::mldsa_create_keypair(uint8_t *public_key, uint8_t *private_key, int alg_type, int public_key_max_buf, int private_key_max_buf){

    DBG_PRINT("ML-DSA KEY Create \n");

    // Buffer length check
    if(alg_type == ML_DSA_44){
        if(public_key_max_buf < OQS_SIG_ml_dsa_65_length_public_key || private_key_max_buf < OQS_SIG_ml_dsa_44_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_65){
        if(public_key_max_buf < OQS_SIG_ml_dsa_65_length_public_key || private_key_max_buf < OQS_SIG_ml_dsa_65_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_87){
        if(public_key_max_buf < OQS_SIG_ml_dsa_65_length_public_key || private_key_max_buf < OQS_SIG_ml_dsa_87_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }
    // Key Create
    OQS_STATUS rc;
    if(alg_type == ML_DSA_44){
        rc = OQS_SIG_ml_dsa_44_keypair(public_key, private_key);
    }
    else if(alg_type == ML_DSA_65){
        rc = OQS_SIG_ml_dsa_65_keypair(public_key, private_key);
    }
    else if(alg_type == ML_DSA_87){
        rc = OQS_SIG_ml_dsa_87_keypair(public_key, private_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("ML-DSA Key Generate fail \n");
        return FAIL;
    }
    DBG_PRINT("ML-DSA Key Generate Success \n");
    return SUCCESS;
}

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
int PqcOqs::mldsa_sign(uint8_t *signature, const uint8_t *message, size_t message_len, int alg_type, const uint8_t *private_key, int private_key_max_buf){

    DBG_PRINT("ML-DSA Sign \n");

    // Buffer length check
    if(alg_type == ML_DSA_44){
        if(private_key_max_buf < OQS_SIG_ml_dsa_44_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_65){
        if(private_key_max_buf < OQS_SIG_ml_dsa_65_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_87){
        if(private_key_max_buf < OQS_SIG_ml_dsa_87_length_secret_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }
    // key Sign
    OQS_STATUS rc;
    size_t signature_len;
    if(alg_type == ML_DSA_44){
        rc = OQS_SIG_ml_dsa_44_sign(signature, &signature_len, message, message_len, private_key);
    }
    else if(alg_type == ML_DSA_65){
        rc = OQS_SIG_ml_dsa_65_sign(signature, &signature_len, message, message_len, private_key);
    }
    else if(alg_type == ML_DSA_87){
        rc = OQS_SIG_ml_dsa_87_sign(signature, &signature_len, message, message_len, private_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("ML-DSA Key Sign fail \n");
        return FAIL;
    }
    DBG_PRINT("ML-DSA Key Sign Success \n");
    return signature_len;
}

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
int PqcOqs::mldsa_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, int alg_type, const uint8_t *public_key, int public_key_max_buf){

    DBG_PRINT("ML-DSA Verify \n");

    // Buffer length check
    if(alg_type == ML_DSA_44){
        if(public_key_max_buf < OQS_SIG_ml_dsa_44_length_public_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_65){
        if(public_key_max_buf < OQS_SIG_ml_dsa_65_length_public_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else if(alg_type == ML_DSA_87){
        if(public_key_max_buf < OQS_SIG_ml_dsa_87_length_public_key){
            DBG_PRINT("Key Buffer not enough \n");
            return FAIL;
        }
    }
    else{ // alg_type not valid
        DBG_PRINT("Key algorithm not valid type \n");
        return FAIL;
    }

    // key Verify
    OQS_STATUS rc;
    if(alg_type == ML_DSA_44){
        rc = OQS_SIG_ml_dsa_44_verify(message, message_len, signature, signature_len, public_key);
    }
    else if(alg_type == ML_DSA_65){
        rc = OQS_SIG_ml_dsa_65_verify(message, message_len, signature, signature_len, public_key);
    }
    else if(alg_type == ML_DSA_87){
        rc = OQS_SIG_ml_dsa_87_verify(message, message_len, signature, signature_len, public_key);
    }
    if(rc != OQS_SUCCESS){
        DBG_PRINT("ML-DSA Key Verify fail \n");
        return FAIL;
    }
    DBG_PRINT("ML-DSA Key Verify Success \n");
    return SUCCESS;
}