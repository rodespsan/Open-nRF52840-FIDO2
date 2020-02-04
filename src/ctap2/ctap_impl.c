/**
* Copyright (c) 2018 makerdiary
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* * Redistributions of source code must retain the above copyright
*   notice, this list of conditions and the following disclaimer.
*
* * Redistributions in binary form must reproduce the above
*   copyright notice, this list of conditions and the following
*   disclaimer in the documentation and/or other materials provided
*   with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "nrf.h"
#include "app_util_platform.h"
#include "bsp.h"
#include "fds.h"

#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_hash.h"
#include "nrf_crypto_error.h"

#include "cbor.h"

#include "ctap_hid_if.h"
#include "ctap_hid.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "cose_key.h"

#include "util.h"

#define NRF_LOG_MODULE_NAME ctap_impl

#include "nrf_log.h"

NRF_LOG_MODULE_REGISTER();




extern uint8_t aes_key[];
extern const uint8_t attestation_cert[];
extern const uint8_t attestation_private_key[];
extern uint16_t attestation_cert_size;
extern uint8_t attestation_private_key_size;

extern bool is_user_button_pressed(void);


/* authentication counter */
uint32_t m_auth_counter = 0;

/* Flag to check fds initialization. */
static bool volatile m_fds_initialized;

/* The record descriptor of counter */
static fds_record_desc_t m_counter_record_desc;

/* A record containing m_auth_counter. */
static fds_record_t const m_counter_record =
{
    .file_id           = CONFIG_COUNTER_FILE,
    .key               = CONFIG_COUNTER_REC_KEY,
    .data.p_data       = &m_auth_counter,
    /* The length of a record is always expressed in 4-byte units (words). */
    .data.length_words = sizeof(m_auth_counter) / sizeof(uint32_t),
};


#ifdef CONFIG_RANDOM_AES_KEY_ENABLED
/* A record containing AES key. */
static fds_record_t const m_aes_key_record =
{
    .file_id           = CONFIG_AES_KEY_FILE,
    .key               = CONFIG_AES_KEY_REC_KEY,
    .data.p_data       = aes_key,
    /* The length of a record is always expressed in 4-byte units (words). */
    .data.length_words = AES_KEY_SIZE / sizeof(uint32_t),
};
#endif /* CONFIG_RANDOM_AES_KEY_ENABLED */


/**@brief Convert a signature to the correct format. For more info:
 * http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always
 * -65-13232-bytes-long
 *
 * @param[in]  p_dest_sig  The output signature.
 * @param[in]  p_src_sig   The input signature.
 *
 * @retval     The output signature size.
 *
 */
static uint16_t signature_convert(uint8_t * p_dest_sig, uint8_t * p_src_sig);


static void fds_evt_handler(fds_evt_t const * p_evt)
{

    switch (p_evt->id)
    {
        case FDS_EVT_INIT:
            if (p_evt->result == FDS_SUCCESS)
            {
                m_fds_initialized = true;
            }
            break;

        case FDS_EVT_WRITE:
        {
            if (p_evt->result == FDS_SUCCESS)
            {
                NRF_LOG_INFO("Record ID:\t0x%04x",  p_evt->write.record_id);
                NRF_LOG_INFO("File ID:\t0x%04x",    p_evt->write.file_id);
                NRF_LOG_INFO("Record key:\t0x%04x", p_evt->write.record_key);
            }
        } break;

        case FDS_EVT_DEL_RECORD:
        {
            if (p_evt->result == FDS_SUCCESS)
            {
                NRF_LOG_INFO("Record ID:\t0x%04x",  p_evt->del.record_id);
                NRF_LOG_INFO("File ID:\t0x%04x",    p_evt->del.file_id);
                NRF_LOG_INFO("Record key:\t0x%04x", p_evt->del.record_key);
            }
        } break;

        default:
            break;
    }
}

/**@brief   Wait for fds to initialize. */
static void wait_for_fds_ready(void)
{
    while (!m_fds_initialized)
    {
        // Just waiting
    }
}


uint32_t ctap_impl_init(void)
{
    ret_code_t ret;
    fds_find_token_t  tok  = {0};

    ret = nrf_crypto_init();
    if(ret != NRF_SUCCESS) return ret;

    /* Register first to receive an event when initialization is complete. */
    (void) fds_register(fds_evt_handler);

    ret = fds_init();
    if(ret != NRF_SUCCESS) return ret;

    wait_for_fds_ready();

    /* update m_auth_counter */
    ret = fds_record_find(CONFIG_COUNTER_FILE, CONFIG_COUNTER_REC_KEY, 
                          &m_counter_record_desc, &tok);
    if(ret == NRF_SUCCESS)
    {
        //blink_led_fast(RED_LED);
        /* A counter is in flash. Let's update it. */
        fds_flash_record_t config = {0};
        
        /* Open the record and read its contents. */
        ret = fds_record_open(&m_counter_record_desc, &config);
        if(ret != NRF_SUCCESS) return ret;

        /* Copy the counter value from flash into m_auth_counter. */
        memcpy(&m_auth_counter, config.p_data, sizeof(m_auth_counter));

        NRF_LOG_INFO("m_auth_counter = %d", m_auth_counter);

        /* Close the record when done reading. */
        ret = fds_record_close(&m_counter_record_desc);
        if(ret != NRF_SUCCESS) return ret;
    }
    else
    {
        /* m_auth_counter not found; write a new one. */
        NRF_LOG_INFO("Writing m_auth_counter...");

        ret = fds_record_write(&m_counter_record_desc, &m_counter_record);
        if(ret != NRF_SUCCESS) return ret;
    }

#ifdef CONFIG_RANDOM_AES_KEY_ENABLED
    /* update AES key */

    //blink_led_fast(GREEN_LED);
    fds_record_desc_t aes_key_record_desc = {0};

    memset(&tok, 0, sizeof(fds_find_token_t));

    ret = fds_record_find(CONFIG_AES_KEY_FILE, CONFIG_AES_KEY_REC_KEY, 
                          &aes_key_record_desc, &tok);
    if(ret == NRF_SUCCESS)
    {
        fds_flash_record_t config = {0};

        /* Open the record and read its contents. */
        ret = fds_record_open(&aes_key_record_desc, &config);
        if(ret != NRF_SUCCESS) return ret;
        
        /* Copy the counter value from flash into aes_key. */
        memcpy(aes_key, config.p_data, AES_KEY_SIZE);

        /* Close the record when done reading. */
        ret = fds_record_close(&aes_key_record_desc);
        if(ret != NRF_SUCCESS) return ret;
        //blink_led_fast(BLUE_LED);
    }
    else
    {
        /* aes_key not found; generate a random one. */
        NRF_LOG_INFO("Generating a random AES key...");

        ret = nrf_crypto_rng_vector_generate(aes_key, AES_KEY_SIZE);
        if(ret != NRF_SUCCESS) return ret;

        ret = fds_record_write(&aes_key_record_desc, &m_aes_key_record);
        if(ret != NRF_SUCCESS) return ret;
        //blink_led_fast(RED_LED);
    }
#endif /* CONFIG_RANDOM_AES_KEY_ENABLED */

    return ret;
}


uint16_t ctap_register(CTAP_REGISTER_REQ * p_req, CTAP_REGISTER_RESP * p_resp, 
                      int flags, uint16_t * p_resp_len)
{
    NRF_LOG_INFO("ctap_register starting...");
    ret_code_t ret;
    size_t len;
    uint8_t buf[64];

    memset(p_resp, 0, sizeof(*p_resp));
    *p_resp_len = 0;
    p_resp->registerId = CTAP_REGISTER_ID;

    if(!is_user_button_pressed())
    {
        return CTAP_SW_CONDITIONS_NOT_SATISFIED;
    }

    bsp_board_led_on(LED_CTAP_WINK);

    /* Generate a key pair */
    nrf_crypto_ecc_private_key_t privkey;
    nrf_crypto_ecc_public_key_t pubkey;
    
    ret = nrf_crypto_ecc_key_pair_generate(NULL, 
          &g_nrf_crypto_ecc_secp256r1_curve_info, &privkey, &pubkey);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to generate key pair! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    /* Export EC Public key */
    len = CTAP_EC_KEY_SIZE * 2;
    ret = nrf_crypto_ecc_public_key_to_raw(&pubkey, buf, &len);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to export EC Public key! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    p_resp->pubKey.pointFormat = CTAP_POINT_UNCOMPRESSED;
    memcpy(&p_resp->pubKey.x[0], buf, CTAP_EC_KEY_SIZE * 2);

    /* Export EC Private key to buf */
    len = CTAP_EC_KEY_SIZE;
    ret = nrf_crypto_ecc_private_key_to_raw(&privkey, buf, &len);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to export EC Private key! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    /* Copy appId to buf after private key */
    memcpy(buf + CTAP_EC_KEY_SIZE, p_req->appId, CTAP_APPID_SIZE);

    nrf_crypto_aes_context_t ecb_encr_128_ctx; // AES ECB encryption context

    /* Init encryption context for 128 bit key */
    ret = nrf_crypto_aes_init(&ecb_encr_128_ctx,
                              &g_nrf_crypto_aes_ecb_128_info,
                              NRF_CRYPTO_ENCRYPT);

    /* Convert EC private key to a key handle -> encrypt it and the appId 
     * using an AES private key */
    len = CTAP_MAX_KH_SIZE;
    ret += nrf_crypto_aes_crypt(&ecb_encr_128_ctx,
                                &g_nrf_crypto_aes_ecb_128_info,
                                NRF_CRYPTO_ENCRYPT,
                                aes_key,
                                NULL,
                                buf,
                                CTAP_EC_KEY_SIZE + CTAP_APPID_SIZE,
                                p_resp->keyHandleCertSig,
                                &len);

    p_resp->keyHandleLen = len;

    ret += nrf_crypto_aes_uninit(&ecb_encr_128_ctx);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("AES encryption failed! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    /* Copy x509 attestation public key certificate */
    memcpy(&p_resp->keyHandleCertSig[p_resp->keyHandleLen], attestation_cert, 
           attestation_cert_size);

    /* Compute SHA256 hash of appId & chal & keyhandle & pubkey */

    nrf_crypto_hash_context_t   hash_context;

    memset(buf, 0, sizeof(buf));

    // Initialize the hash context
    ret = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);

    /* hash update buf[0] = 0x00 */
    ret += nrf_crypto_hash_update(&hash_context, buf, 1);

    /* The application parameter [32 bytes] from 
     * the registration request message. */
    ret += nrf_crypto_hash_update(&hash_context, p_req->appId, CTAP_APPID_SIZE);

    /* The challenge parameter [32 bytes] from 
     * the registration request message. */
    ret += nrf_crypto_hash_update(&hash_context, p_req->chal, CTAP_CHAL_SIZE);

    /* The key handle [variable length] */
    ret += nrf_crypto_hash_update(&hash_context, p_resp->keyHandleCertSig, 
                                  p_resp->keyHandleLen);

    /* The user public key [65 bytes]. */
    ret += nrf_crypto_hash_update(&hash_context, (uint8_t *)&p_resp->pubKey, 
                                  CTAP_EC_POINT_SIZE);

    len = 32;
    ret += nrf_crypto_hash_finalize(&hash_context, buf, &len);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to calculate hash! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    nrf_crypto_ecc_private_key_t sign_private_key;
    /* Sign the SHA256 hash using the attestation key */
    ret = nrf_crypto_ecc_private_key_from_raw(
                                        &g_nrf_crypto_ecc_secp256r1_curve_info,
                                        &sign_private_key,
                                        attestation_private_key,
                                        attestation_private_key_size);

    nrf_crypto_ecdsa_secp256r1_signature_t m_signature;
    size_t m_signature_size = sizeof(m_signature);

    ret += nrf_crypto_ecdsa_sign(NULL,
                                 &sign_private_key,
                                 buf,
                                 len,
                                 m_signature,
                                 &m_signature_size);
    // Key deallocation
    ret += nrf_crypto_ecc_private_key_free(&sign_private_key);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to generate signature! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    m_signature_size = signature_convert(
        &p_resp->keyHandleCertSig[p_resp->keyHandleLen + attestation_cert_size], 
        m_signature);

    *p_resp_len = p_resp->keyHandleCertSig - (uint8_t *)p_resp 
                  + p_resp->keyHandleLen + attestation_cert_size 
                  + m_signature_size;

    return CTAP_SW_NO_ERROR;
}



uint16_t ctap_authenticate(CTAP_AUTHENTICATE_REQ * p_req, 
                          CTAP_AUTHENTICATE_RESP * p_resp, 
                          int flags, uint16_t * p_resp_len)
{
    NRF_LOG_INFO("ctap_authenticate starting...");

    ret_code_t ret;
    size_t len;
    uint8_t buf[CTAP_EC_KEY_SIZE + CTAP_APPID_SIZE];

    *p_resp_len = 0;

    if(flags == CTAP_AUTH_ENFORCE && !is_user_button_pressed())
    {
        return CTAP_SW_CONDITIONS_NOT_SATISFIED;
    }

    bsp_board_led_on(LED_CTAP_WINK);

    /* Convert key handle to EC private key -> 
     * decrypt it using AES private key */
    nrf_crypto_aes_context_t ecb_decr_128_ctx; // AES ECB decryption context

    /* Init decryption context for 128 bit key */
    ret = nrf_crypto_aes_init(&ecb_decr_128_ctx,
                              &g_nrf_crypto_aes_ecb_128_info,
                              NRF_CRYPTO_DECRYPT);

    len = sizeof(buf);
    ret += nrf_crypto_aes_crypt(&ecb_decr_128_ctx,
                                &g_nrf_crypto_aes_ecb_128_info,
                                NRF_CRYPTO_DECRYPT,
                                aes_key,
                                NULL,
                                p_req->keyHandle,
                                p_req->keyHandleLen,
                                buf,
                                &len);
    ret += nrf_crypto_aes_uninit(&ecb_decr_128_ctx);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("AES decryption failed! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;        
    }

    if(memcmp(&buf[CTAP_EC_KEY_SIZE], p_req->appId, CTAP_APPID_SIZE) != 0)
    {
        NRF_LOG_ERROR("APPID MISMATCH!");
        return CTAP_SW_WRONG_DATA;
    }

    uint32_big_encode(m_auth_counter, p_resp->ctr);
    m_auth_counter++;
    /* Write the updated record to flash. */
    ret = fds_record_update(&m_counter_record_desc, &m_counter_record);
    APP_ERROR_CHECK(ret);

    p_resp->flags = CTAP_AUTH_FLAG_TUP;

    /* Get private key */
    nrf_crypto_ecc_private_key_t private_key;
    ret = nrf_crypto_ecc_private_key_from_raw(
                                        &g_nrf_crypto_ecc_secp256r1_curve_info,
                                        &private_key,
                                        buf,
                                        CTAP_EC_KEY_SIZE);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to get private key from raw! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    /* Compute SHA256 hash of appId & user presence & counter & chal */
    nrf_crypto_hash_context_t   hash_context;

    // Initialize the hash context
    ret = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
    
    /* hash update appId */
    ret += nrf_crypto_hash_update(&hash_context, p_req->appId, CTAP_APPID_SIZE);

    /* hash update user presence */
    ret += nrf_crypto_hash_update(&hash_context, &p_resp->flags, 1);

    /* hash update counter */
    ret += nrf_crypto_hash_update(&hash_context, p_resp->ctr, CTAP_CTR_SIZE);

    /* hash update chal */
    ret += nrf_crypto_hash_update(&hash_context, p_req->chal, CTAP_CHAL_SIZE);

    len = 32;
    ret += nrf_crypto_hash_finalize(&hash_context, buf, &len);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to calculate hash! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    /* Sign the SHA256 hash using the private key */
    nrf_crypto_ecdsa_secp256r1_signature_t m_signature;
    size_t m_signature_size = sizeof(m_signature);

    ret = nrf_crypto_ecdsa_sign(NULL,
                                &private_key,
                                buf,
                                len,
                                m_signature,
                                &m_signature_size);

    // Key deallocation
    ret += nrf_crypto_ecc_private_key_free(&private_key);
    if(ret != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Fail to generate signature! [code = %d]", ret);
        return CTAP_SW_INS_NOT_SUPPORTED;
    }

    m_signature_size = signature_convert(p_resp->sig, m_signature);

    *p_resp_len = p_resp->sig - (uint8_t *)p_resp + m_signature_size;

    return CTAP_SW_NO_ERROR;
}


/**@brief Convert a signature to the correct format. For more info:
 * http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always
 * -65-13232-bytes-long
 *
 * @param[in]  p_dest_sig  The output signature.
 * @param[in]  p_src_sig   The input signature.
 *
 * @retval     The output signature size.
 *
 */
static uint16_t signature_convert(uint8_t * p_dest_sig, uint8_t * p_src_sig)
{
    int idx = 0;

    p_dest_sig[idx++] = 0x30; //header: compound structure

    uint8_t *p_len = &p_dest_sig[idx];

    p_dest_sig[idx++] = 0x44; //total length (32 + 32 + 2 + 2) at least
    
    p_dest_sig[idx++] = 0x02; //header: integer

    if(p_src_sig[0] > 0x7f)
    {
        p_dest_sig[idx++] = 33;
        p_dest_sig[idx++] = 0;
        (*p_len)++;
    }
    else
    {
        p_dest_sig[idx++] = 32;
    }

    memcpy(&p_dest_sig[idx], p_src_sig, 32);
    idx += 32;

    p_dest_sig[idx++] = 0x02;

    if(p_src_sig[32] > 0x7f)
    {
        p_dest_sig[idx++] = 33;
        p_dest_sig[idx++] = 0;
        (*p_len)++;
    }
    else
    {
        p_dest_sig[idx++] = 32;
    }

    memcpy(&p_dest_sig[idx], p_src_sig+32, 32);
    idx += 32;

    return idx;  // new signature size
}

/**@brief Initialize a CBOR CTAP_RESPONSE. Function obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 *
 * @param[in]  resp   CBOR CTAP_RESPONSE.
 * 
 */
void ctap_response_init(CTAP_RESPONSE * resp)
{
    memset(resp, 0, sizeof(CTAP_RESPONSE));
    resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}

uint8_t parse_fixed_byte_string(CborValue * map, uint8_t * dst, unsigned int len)
{
    size_t sz;
    int ret;
    if (cbor_value_get_type(map) == CborByteStringType)
    {
        sz = len;
        ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
        if(ret != CborNoError) { return ERR_OTHER; }
        //check_ret(ret);
        if (sz != len)
        {
            //printf2(TAG_ERR, "error byte string is different length (%d vs %d)\r\n", len, sz);
            return CTAP1_ERR_INVALID_LENGTH;
        }
    }
    else
    {
        //printf2(TAG_ERR, "error, CborByteStringType expected\r\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    return ERR_NONE;
}

/**@brief Parse Relay Party ID CBOR from Make Credential request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_rp_id(struct rpId * rp, CborValue * val)
{
    size_t sz = DOMAIN_NAME_MAX_SIZE;
    if (cbor_value_get_type(val) != CborTextStringType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    int ret = cbor_value_copy_text_string(val, (char*)rp->id, &sz, NULL);
    if (ret == CborErrorOutOfMemory)
    {
        //printf2(TAG_ERR,"Error, RP_ID is too large\n");
        blink_led_fast(PWR_LED);
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
    rp->id[DOMAIN_NAME_MAX_SIZE] = 0;     // Extra byte defined in struct.
    rp->size = sz;
    return 0;
}

/**@brief Parse Relay Party CBOR from Make Credential request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_rp(struct rpId * rp, CborValue * val)
{
    size_t sz, map_length;
    char key[8];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    ret = cbor_value_get_map_length(val, &map_length);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    rp->size = 0;

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            blink_led_fast(BLUE_LED);
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strcmp(key, "id") == 0)
        {
            ret = parse_rp_id(rp, &map);
            if (ret != 0)
            {
                return ret;
            }
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = RP_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char*)rp->name, &sz, NULL);
            /*if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                //blink_led_fast(GREEN_LED);
                //return CTAP2_ERR_LIMIT_EXCEEDED;
            }*/
            rp->name[RP_NAME_LIMIT - 1] = 0;
        }
        else
        {
            //printf1(TAG_PARSE,"ignoring key %s for RP map\n", key);
        }

        ret = cbor_value_advance(&map);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    }
    if (rp->size == 0)
    {
        //printf2(TAG_ERR,"Error, no RPID provided\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }


    return 0;
}

/**@brief Parse the user PublicKeyCredentialUserEntity from MakeCredential CBOR request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_user(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[24];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        //printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    ret = cbor_value_get_map_length(val, &map_length);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            //printf2(TAG_ERR,"Error, expecting text string type for user map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, (char *)key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            //printf2(TAG_ERR,"Error, rp map key is too large\n");
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }

        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

        if (strcmp((const char*)key, "id") == 0)
        {

            if (cbor_value_get_type(&map) != CborByteStringType)
            {
                //printf2(TAG_ERR,"Error, expecting byte string type for rp map value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }

            sz = USER_ID_MAX_SIZE;
            ret = cbor_value_copy_byte_string(&map, MC->credInfo.user.id, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                //printf2(TAG_ERR,"Error, USER_ID is too large\n");
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            MC->credInfo.user.id_size = sz;
            if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
        }
        else if (strcmp((const char *)key, "name") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                //printf2(TAG_ERR,"Error, expecting text string type for user.name value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = USER_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.name, &sz, NULL);
            /*if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }*/
            MC->credInfo.user.name[USER_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "displayName") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                //printf2(TAG_ERR,"Error, expecting text string type for user.displayName value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = DISPLAY_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.displayName, &sz, NULL);
            /*if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }*/
            MC->credInfo.user.displayName[DISPLAY_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "icon") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                //printf2(TAG_ERR,"Error, expecting text string type for user.icon value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = ICON_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.icon, &sz, NULL);
            /*if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }*/
            MC->credInfo.user.icon[ICON_LIMIT - 1] = 0;

        }
        else
        {
            //printf1(TAG_PARSE,"ignoring key %s for user map\n", key);
        }

        ret = cbor_value_advance(&map);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    }

    MC->paramsParsed |= PARAM_user;

    return ERR_NONE;
}

/**@brief Parse one parameter from pubKeyCredParams from MakeCredential CBOR request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_pub_key_cred_param(CborValue * val, uint8_t * cred_type, int32_t * alg_type)
{
    CborValue cred;
    CborValue alg;
    int ret;
    uint8_t type_str[16];
    size_t sz = sizeof(type_str);

    if (cbor_value_get_type(val) != CborMapType)
    {
        //printf2(TAG_ERR,"error, expecting map type, got %s\n", cbor_value_get_type_string(val));
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_map_find_value(val, "type", &cred);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
    ret = cbor_value_map_find_value(val, "alg", &alg);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    if (cbor_value_get_type(&cred) != CborTextStringType)
    {
        //printf2(TAG_ERR,"Error, parse_pub_key could not find credential param\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (cbor_value_get_type(&alg) != CborIntegerType)
    {
        //printf2(TAG_ERR,"Error, parse_pub_key could not find alg param\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    ret = cbor_value_copy_text_string(&cred, (char*)type_str, &sz, NULL);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    type_str[sizeof(type_str) - 1] = 0;

    if (strcmp((const char*)type_str, "public-key") == 0)
    {
        *cred_type = PUB_KEY_CRED_PUB_KEY;
    }
    else
    {
        *cred_type = PUB_KEY_CRED_UNKNOWN;
    }

    ret = cbor_value_get_int_checked(&alg, (int*)alg_type);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    return ERR_NONE;
}

/**@brief Check if public key credential+algorithm type is supported. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
static int pub_key_cred_param_supported(uint8_t cred, int32_t alg)
{
    if (cred == PUB_KEY_CRED_PUB_KEY)
    {
        if (alg == COSE_ALG_ES256)
        {
            return  CREDENTIAL_IS_SUPPORTED;
        }
    }

    return  CREDENTIAL_NOT_SUPPORTED;
}

/**@brief Parse pubKeyCredParams from MakeCredential CBOR request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val)
{
    size_t arr_length;
    uint8_t cred_type;
    int32_t alg_type;
    int ret;
    unsigned int i;
    CborValue arr;


    if (cbor_value_get_type(val) != CborArrayType)
    {
        //printf2(TAG_ERR,"error, expecting array type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&arr);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    ret = cbor_value_get_array_length(val, &arr_length);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) != 0)
        {
            return ret;
        }
        ret = cbor_value_advance(&arr);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
    }

    ret = cbor_value_enter_container(val,&arr);
    if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) == 0)
        {
            if (pub_key_cred_param_supported(cred_type, alg_type) == CREDENTIAL_IS_SUPPORTED)
            {
                MC->credInfo.publicKeyCredentialType = cred_type;
                MC->credInfo.COSEAlgorithmIdentifier = alg_type;
                MC->paramsParsed |= PARAM_pubKeyCredParams;
                return 0;
            }
        }
        ret = cbor_value_advance(&arr);
        if(ret != CborNoError) { return CTAP2_ERR_INVALID_CBOR; }
    }

    //printf2(TAG_ERR,"Error, no public key credential parameters are supported!\n");
    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

/**@brief Parse MakeCredential CBOR request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, ctap_channel_t *p_ch)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it;
    CborValue map;
    uint8_t * request = p_ch->req + 1;  // First byte is command requested, then, request starts at second byte
    
    memset(MC, 0, sizeof(CTAP_makeCredential));
    
    ret = cbor_parser_init(request, p_ch->bcnt, CborValidateCanonicalFormat, &parser, &it);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
    
    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        bsp_board_leds_off();
        bsp_board_led_on(RED_LED);
        ctap_hid_error_response(p_ch->cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    
    ret = cbor_value_enter_container(&it,&map);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; }
    
    ret = cbor_value_get_map_length(&it, &map_length);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
    
    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            bsp_board_leds_off();
            bsp_board_led_on(RED_LED);
            ctap_hid_error_response(p_ch->cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
        ret = cbor_value_advance(&map);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
        bsp_board_leds_off();
        switch(key)
        {
            case MC_clientDataHash:
                ret = parse_fixed_byte_string(&map, MC->clientDataHash, CLIENT_DATA_HASH_SIZE);
                if (ret == ERR_NONE)
                {
                    MC->paramsParsed |= PARAM_clientDataHash;
                    bsp_board_led_on(PWR_LED);
                }
                else{
                    ctap_hid_error_response(p_ch->cid, ret);
                    blink_led_fast(RED_LED);
                }
                break;
            case MC_rp:
                ret = parse_rp(&MC->rp, &map);
                if (ret == ERR_NONE)
                {
                    MC->paramsParsed |= PARAM_rp;
                    bsp_board_led_on(RED_LED);
                }
                else
                {
                    ctap_hid_error_response(p_ch->cid, ret);
                    blink_led_fast(RED_LED);
                }
                break;
            case MC_user:
                ret = parse_user(MC, &map);
                if (ret == ERR_NONE)
                    bsp_board_led_on(GREEN_LED);
                else
                {
                    ctap_hid_error_response(p_ch->cid, ret);
                    blink_led_fast(RED_LED);
                }
                break;
            case MC_pubKeyCredParams:
                ret = parse_pub_key_cred_params(MC, &map);
                if (ret == ERR_NONE)
                    bsp_board_led_on(BLUE_LED);
                else
                {
                    ctap_hid_error_response(p_ch->cid, ret);
                    blink_led_fast(RED_LED);
                }
                break;
            case MC_excludeList:                    // TO DO
                bsp_board_led_on(RED_LED);
                bsp_board_led_on(GREEN_LED);
                break;
            case MC_extensions:                     // TO DO
                bsp_board_led_on(RED_LED);
                bsp_board_led_on(BLUE_LED);
                break;
            case MC_options:                        // TO DO
                bsp_board_led_on(GREEN_LED);
                bsp_board_led_on(BLUE_LED);
                break;
            case MC_pinAuth:                        // TO DO
                bsp_board_led_on(PWR_LED);
                bsp_board_led_on(RED_LED);
                break;
            case MC_pinProtocol:                    // TO DO
                bsp_board_led_on(PWR_LED);
                bsp_board_led_on(GREEN_LED);
                break;
            default:                                // TO DO
                bsp_board_led_on(PWR_LED);
                bsp_board_led_on(BLUE_LED);
                break;
        }
        cbor_value_advance(&map);
        //bsp_board_led_invert(BLUE_LED);
        if(i == 4)
            return ERR_NONE;
    }
    
    return ret;
    //return ERR_NONE;
}

/**@brief Parse PublicKeyCredentialDescriptors from getAssertion. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_credential_descriptor(CborValue * arr, CTAP_credentialDescriptor * cred)
{
    int ret;
    size_t buflen;
    char type[12];
    CborValue val;
    cred->type = 0;
    
    if (cbor_value_get_type(arr) != CborMapType) return CTAP2_ERR_INVALID_CBOR_TYPE;
    
    ret = cbor_value_map_find_value(arr, "id", &val);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    if (cbor_value_get_type(&val) != CborByteStringType) return CTAP2_ERR_MISSING_PARAMETER;
    
    buflen = sizeof(CTAP_credentialSource);
    
    ret = cbor_value_copy_byte_string(&val, (uint8_t*)&cred->credential.id, &buflen, NULL);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    if (buflen == CTAP_MAX_KH_SIZE)
    {
        cred->type = PUB_KEY_CRED_CTAP1;
        blink_led_fast(RED_LED);
    }
    else if (buflen != sizeof(CTAP_credentialSource))
    {
        // Ignoring credential is incorrect length, treating as custom
        cred->type = PUB_KEY_CRED_CUSTOM;
        blink_led_fast(RED_LED);
    }
    
    ret = cbor_value_map_find_value(arr, "type", &val);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    if (cbor_value_get_type(&val) != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;
    
    buflen = sizeof(type);
    ret = cbor_value_copy_text_string(&val, type, &buflen, NULL);
    if (ret == CborErrorOutOfMemory)
        cred->type = PUB_KEY_CRED_UNKNOWN;
    else
    {
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }
    
    if (strncmp(type, "public-key",11) == 0)
    {
        if (0 == cred->type)
        {
            cred->type = PUB_KEY_CRED_PUB_KEY;
            //blink_led_fast(WHITE_LED);
        }
        
    }
    else
    {
        cred->type = PUB_KEY_CRED_UNKNOWN;
        blink_led_fast(RED_LED);
    }
    
    //blink_led_fast(CYAN_LED);
    return ERR_NONE;
}

/**@brief Decrypt credentialSource using AES key
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
int decrypt_credential_source(uint8_t *credentialSourceEncrypted, uint8_t *credentialSourceDecrypted)
{
    ret_code_t err_code;
    
    size_t data_out_size = CTAP_CREDENTIAL_SOURCE_SIZE;
    
    uint8_t *iv = credentialSourceEncrypted;
    uint8_t *credentialSourceEncryptedBuf = credentialSourceEncrypted + AES_KEY_SIZE;
    uint8_t *credentialSourceDecryptedBuf = credentialSourceDecrypted + AES_KEY_SIZE;
    
    memmove(credentialSourceDecrypted, iv, AES_KEY_SIZE);   // Copying IV
    
    nrf_crypto_aes_context_t aes_ctr_128_decr_ctx; // AES CTR decryption context
    
    err_code = nrf_crypto_aes_crypt(
        &aes_ctr_128_decr_ctx,                      // Context
        &g_nrf_crypto_aes_ctr_128_info,             // AES mode
        NRF_CRYPTO_DECRYPT,                         // Decrypt operation
        aes_key,                                    // AES key
        iv,                                         // Initialization Vector (IV) Nonce and Counter
        credentialSourceEncryptedBuf,                   // Data to decrypt
        CTAP_CREDENTIAL_SOURCE_SIZE,                // Data size
        credentialSourceDecryptedBuf,               // Plaintext
        &data_out_size);                            // Plaintext size
    if( err_code != NRF_SUCCESS )
    {
        bsp_board_leds_off();
        blink_led_fast(RED_LED);
        return err_code;
    }
    APP_ERROR_CHECK(err_code);
    
    return ERR_NONE;
}

/**@brief Recovers the private key from a CredentialID (Credential Source encrypted)
 *
 * @param[in]   rp              Pointer to a Relying Party struct
 * @param[in]   desc            Pointer to the Credential Descriptor to verify
 * @param[out]  private_key     Pointer to store the private key recovered
 *
 * @retval     ERR_NONE if the Credential Descriptor is valid
 */
int ctap_recover_private_key(struct rpId * rp, CTAP_credentialDescriptor *desc, nrf_crypto_ecc_private_key_t *private_key)
{
    int ret;
    
    uint8_t credentialSourceDec[sizeof(CTAP_credentialSource)];
        
    CTAP_credentialSource *credentialSource = (CTAP_credentialSource *)credentialSourceDec;
    memset(credentialSource, 0, sizeof(CTAP_credentialSource));
    
    ret = decrypt_credential_source((uint8_t *)&desc->credential.id, credentialSourceDec);
    if( ret != NRF_SUCCESS ){ blink_led_fast(RED_LED); return ret;}
    
    if (memcmp(rp->id, credentialSource->rpId, DOMAIN_NAME_MAX_SIZE + 1) != 0)
    {
        blink_led_fast(RED_LED);
        return CTAP2_ERR_INVALID_CREDENTIAL;
    }
    
    size_t private_key_raw_size = CTAP_EC_KEY_SIZE;
        
    // Convert raw key to private_key struct
    ret = nrf_crypto_ecc_private_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,     // Info structure
        private_key,                                // Output private key struct
        credentialSource->privateKey,               // Pointer to buffer containing a raw private key
        private_key_raw_size                        // Size in bytes of raw private key
    );
    if( ret != NRF_SUCCESS ){ blink_led_fast(RED_LED); return ret;}
    
    //blink_led_fast(CYAN_LED);
    return ERR_NONE;
}

/**@brief Authenticate that this credentialDecriptor belongs to this authenticator and Relying Party. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 * @param[in]  rp   Pointer to a Relying Party struct
 * @param[in]  desc Pointer to the Credential Descriptor to verify
 *
 * @retval     ERR_NONE if the Credential Descriptor is valid
 */
int ctap_authenticate_credential(struct rpId * rp, CTAP_credentialDescriptor * desc)
{
    int ret;
    
    if( desc->type == PUB_KEY_CRED_PUB_KEY )
    {
        uint8_t credentialSourceDec[sizeof(CTAP_credentialSource)];
        
        CTAP_credentialSource *credentialSource = (CTAP_credentialSource *)credentialSourceDec;
        memset(credentialSource, 0, sizeof(CTAP_credentialSource));
        
        ret = decrypt_credential_source((uint8_t *)&desc->credential.id, credentialSourceDec);
        if( ret != NRF_SUCCESS ){ blink_led_fast(RED_LED); return ret;}
        
        if (memcmp(rp->id, credentialSource->rpId, DOMAIN_NAME_MAX_SIZE + 1) != 0)
        {
            blink_led_fast(RED_LED);
            return CTAP2_ERR_INVALID_CREDENTIAL;
        }
        //blink_led_fast(YELLOW_LED);
    }
    else
    {
        blink_led_fast(RED_LED);
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    
    
    
    /*if (memcmp(credentialIdDec + AES_KEY_SIZE, credentialSourceWithOutIV, CTAP_CREDENTIAL_SOURCE_SIZE) != 0)
    {
        bsp_board_leds_off();
        blink_led_fast(RED_LED);
        return CTAP2_ERR_CREDENTIAL_NOT_VALID;
    }*/
    
    
    //blink_led_fast(CYAN_LED);
    return ERR_NONE;
}

/**@brief Parse allowList sequence of PublicKeyCredentialDescriptors from getAssertion. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t parse_allow_list(CTAP_getAssertion * GA, CborValue * it)
{
    CborValue arr;
    size_t len;
    int ret;
    unsigned int i;
    CTAP_credentialDescriptor * cred;
    
    if (cbor_value_get_type(it) != CborArrayType) return CTAP2_ERR_INVALID_CBOR_TYPE;
    
    ret = cbor_value_enter_container(it,&arr);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    ret = cbor_value_get_array_length(it, &len);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    GA->credLen = 0;
    
    /*bsp_board_leds_off();
    blinkn_led(BLUE_LED, len);
    return len;*/
    
    for(i = 0; i < len; i++)
    {
        if (GA->credLen >= ALLOW_LIST_MAX_SIZE)
            return CTAP2_ERR_TOO_MANY_ELEMENTS;
        cred = nrf_malloc(sizeof(CTAP_credentialDescriptor));
        
        //cred = &GA->creds[i];
        ret = parse_credential_descriptor(&arr,cred);
        if(ret != CborNoError) return ret;
        
        ret = ctap_authenticate_credential(&GA->rp, cred);
        if( ret == ERR_NONE )
        {
            GA->creds[GA->credLen] = cred;
            GA->credLen += 1;
        }
        else
            nrf_free(cred);
        
        ret = cbor_value_advance(&arr);
        if(ret != CborNoError) return ret;
    }
    
    //blink_led_fast(PWR_LED);
    return ERR_NONE;
}

/**@brief Parse MakeCredential CBOR request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c
 *
 *
 */
uint8_t ctap_parse_get_assertion(CTAP_getAssertion * GA, uint8_t * request, int length)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it;
    CborValue map;
    
    memset(GA, 0, sizeof(CTAP_getAssertion));
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    
    ret = cbor_value_enter_container(&it,&map);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    ret = cbor_value_get_map_length(&it, &map_length);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    
    /*bsp_board_leds_off();
    blinkn_led(WHITE_LED, map_length);
    return map_length;*/
    
    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType) return CTAP2_ERR_INVALID_CBOR_TYPE;
        
        ret = cbor_value_get_int_checked(&map, &key);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        
        ret = cbor_value_advance(&map);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        
        switch(key)
        {
            case GA_clientDataHash:
                ret = parse_fixed_byte_string(&map, GA->clientDataHash, CLIENT_DATA_HASH_SIZE);
                if(ret != CborNoError) return ret;
                GA->clientDataHashPresent = 1;
                break;
            case GA_rpId:
                ret = parse_rp_id(&GA->rp, &map);
                if(ret != CborNoError) return ret;
                break;
            case GA_allowList:
                ret = parse_allow_list(GA, &map);
                if(ret != CborNoError) return ret;
                break;
            case GA_extensions:
                break;
            case GA_options:
                break;
            case GA_pinAuth:
                break;
            case GA_pinProtocol:
                break;
            
        }
        cbor_value_advance(&map);
        if(i == 2)
            break;
    }
    
    //blink_led_fast(GREEN_LED);
    return ERR_NONE;
}

/**@brief CBOR Encoding for COSE Key. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
static int ctap_add_cose_key(CborEncoder * cose_key, uint8_t * x, uint8_t * y, uint8_t credtype, int32_t algtype)
{
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        ret = cbor_encode_int(&map, COSE_KEY_KTY_EC2);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        ret = cbor_encode_int(&map, algtype);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        ret = cbor_encode_int(&map, COSE_KEY_CRV_P256);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        ret = cbor_encode_byte_string(&map, x, 32);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
        ret = cbor_encode_byte_string(&map, y, 32);
        if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    ret = cbor_encoder_close_container(cose_key, &map);
    if(ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    return ERR_NONE;
}



/**@brief Creates authData for authenticatorMakeCredential Response. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
static int ctap_make_auth_data(ctap_channel_t *p_ch, struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, uint32_t * len, CTAP_credInfo * credInfo, nrf_crypto_ecc_private_key_t *private_key)
{
    CborEncoder cose_key;
    
    unsigned int auth_data_sz = sizeof(CTAP_authDataHeader);
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;
    
    uint8_t * cose_key_buf = auth_data_buf + sizeof(CTAP_authData);
    
    ret_code_t err_code;
    
    static nrf_crypto_hash_context_t hash_context;
    static nrf_crypto_hash_sha256_digest_t hash_digest;
    
    size_t digest_size = sizeof(hash_digest);
    
    err_code = nrf_crypto_hash_calculate(
            &hash_context,                       // Context
            &g_nrf_crypto_hash_sha256_info,      // Info structure
            rp->id,                              // Input buffer
            rp->size,                            // Input size
            authData->head.rpIdHash,             // Result buffer
            &digest_size);                       // Result size
    
    if( err_code != NRF_SUCCESS )
    {
        bsp_board_leds_off();
        blink_led_fast(RED_LED);
        return err_code;
    }
    APP_ERROR_CHECK(err_code);
    
    authData->head.signCount = m_auth_counter;      // Using the global signature counter
    //authData->head.signCount = 0;                 // Setting counter to 0
    
    
    authData->head.flags = (1 << 0);    // User presence flag, 1 means the user is present.
    
    if (credInfo != NULL)
    {
        authData->head.flags |= (1 << 6);   //include attestation data
        
        cbor_encoder_init(&cose_key, cose_key_buf, *len - sizeof(CTAP_authData), 0);
        
        // Copying the CTAP_AAGUID
        memmove(authData->attest.aaguid, CTAP_AAGUID, 16);
        
        // Calculating the attest Credential Id size
        authData->attest.credLenL =  sizeof(CTAP_credentialSource) & 0x00FF;
        authData->attest.credLenH = (sizeof(CTAP_credentialSource) & 0xFF00) >> 8;
        
        uint8_t credential_source_buffer[sizeof(CTAP_credentialSource)];
        
        CTAP_credentialSource *credentialSource = (CTAP_credentialSource *)credential_source_buffer;
        uint8_t *credentialSourceWithOutIV = credential_source_buffer + AES_KEY_SIZE;
        
        // Generating credential ID
        memset(credentialSource, 0, sizeof(CTAP_credentialSource));
        
        credentialSource->type = PUB_KEY_CRED_PUB_KEY;   // Credential Source Type
        
        
        nrf_crypto_ecc_public_key_t public_key;         // Public key structure
        
        // Private and public key pair generation
        err_code = nrf_crypto_ecc_key_pair_generate(
            NULL,                                       // Keygen context (NULL)
            &g_nrf_crypto_ecc_secp256r1_curve_info,     // Info structure
            private_key,                               // Output private key
            &public_key);                               // Output public key
        
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        size_t raw_private_key_size = CTAP_EC_KEY_SIZE;
        
        // Convert a private key to a raw data and stores it on CredentialSource
        err_code = nrf_crypto_ecc_private_key_to_raw(
            private_key,                               // Private key structure to convert to raw
            credentialSource->privateKey,               // Output for raw private key
            &raw_private_key_size);                     // Size of raw private key
        
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        memmove(credentialSource->rpId, rp->id, DOMAIN_NAME_MAX_SIZE + 1);          // Copying Relying Party Id
        memmove(credentialSource->userHandle, credInfo->user.id, USER_ID_MAX_SIZE); // Copying userHandle
        
        uint8_t credentialId[sizeof(CTAP_credentialSource)];                // IV + CredentialSource Cipher
        uint8_t *iv = credentialId;                                         // IV pointing at first 16 bytes of CredentialId
        uint8_t *credential_source_cipher = credentialId + AES_KEY_SIZE;    // Starts after IV (16 bytes)
        
        memset(iv, 0, AES_KEY_SIZE);    // Initializing IV (First 16 bytes) to 0 (counter starts on 0)
        
        // Initializing IV (First 8 bytes) with a nonce
        err_code = nrf_crypto_rng_vector_generate(iv, AES_KEY_SIZE/2);
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        size_t data_out_size;
        
        nrf_crypto_aes_context_t aes_ctr_128_encr_ctx; // AES CTR encryption context
        
        err_code = nrf_crypto_aes_crypt(
            &aes_ctr_128_encr_ctx,                      // Context
            &g_nrf_crypto_aes_ctr_128_info,             // AES mode
            NRF_CRYPTO_ENCRYPT,                         // Ecrypt operation
            aes_key,                                    // AES key
            iv,                                         // Initialization Vector (IV) Nonce and Counter
            credentialSourceWithOutIV,                  // Data to encrypt
            CTAP_CREDENTIAL_SOURCE_SIZE,                // Data size
            credential_source_cipher,                   // Ciphertext
            &data_out_size);                            // Ciphertext size
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        APP_ERROR_CHECK(err_code);
        
        // Copying Credential Source Encrypted as Credential ID inside authData
        memmove(&authData->attest.credentialId, credentialId, sizeof(CTAP_credentialSource));
        
        size_t raw_public_key_size = CTAP_EC_KEY_SIZE * 2;
        uint8_t raw_public_key[ raw_public_key_size ];      // 32 bytes each EC point
        
        // Convert a public key to a raw data and stores it on CredentialSource
        err_code = nrf_crypto_ecc_public_key_to_raw(
            &public_key,                                // Public key structure to convert to raw
            raw_public_key,                             // Output for raw public key
            &raw_public_key_size);                      // Size of raw public key
        
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        uint8_t * x = raw_public_key;           // Point x from Public Key Eliptic Curve
        uint8_t * y = raw_public_key + 32;      // Point y from Public Key Eliptic Curve
        err_code = ctap_add_cose_key(&cose_key, x, y, credInfo->publicKeyCredentialType, credInfo->COSEAlgorithmIdentifier);
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
        
        // Verifying credentialSource Encryption/Decryption
        
        uint8_t credentialIdDec[sizeof(CTAP_credentialSource)]; 
        
        err_code = decrypt_credential_source((uint8_t *)&authData->attest.credentialId, credentialIdDec);
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
        if (memcmp(credentialIdDec + AES_KEY_SIZE, credentialSourceWithOutIV, CTAP_CREDENTIAL_SOURCE_SIZE) != 0)
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return CTAP2_ERR_CREDENTIAL_NOT_VALID;
        }
        
        // Key deallocation
        err_code = nrf_crypto_ecc_public_key_free(&public_key);
        if( err_code != NRF_SUCCESS )
        {
            bsp_board_leds_off();
            blink_led_fast(RED_LED);
            return err_code;
        }
        
    }
    
    *len = auth_data_sz;
    return ERR_NONE;
}

/**@brief Calculates the signature for the self attestation format. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, nrf_crypto_ecdsa_secp256r1_signature_t signature, size_t *signature_size, nrf_crypto_ecc_private_key_t *private_key)
{
    // calculate attestation sig
    ret_code_t err_code;
    static nrf_crypto_hash_context_t hash_context;
    static nrf_crypto_hash_sha256_digest_t hash_digest;
    size_t hash_size;
    
    //blink_led_fast(BLUE_LED);
    
    // Initialize the hash context 
    err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
    if (err_code != ERR_NONE) return err_code;
    
    //blink_led_fast(CYAN_LED);
    
    //Hashing authData
    err_code = nrf_crypto_hash_update(&hash_context, data, datalen);
    if (err_code != ERR_NONE) return err_code;
    
    //blink_led_fast(WHITE_LED);
    
    //Hashing clientDataHash
    err_code = nrf_crypto_hash_update(&hash_context, clientDataHash, CLIENT_DATA_HASH_SIZE);
    if (err_code != ERR_NONE) return err_code;
    
    //blink_led_fast(MAGENTA_LED);
    
    // Run the finalize when all data has been fed to the update function.
    // This gives you the result in hash_digest
    err_code = nrf_crypto_hash_finalize(&hash_context, hash_digest, &hash_size);
    if (err_code != ERR_NONE) return err_code;
    
    //blink_led_fast(CYAN_LED);
    
    nrf_crypto_ecdsa_sign_context_t sign_context;
    
    
    err_code = nrf_crypto_ecdsa_sign(
        &sign_context,          // Context
        private_key,            // Private key
        hash_digest,            // Message hash
        hash_size,              // Hash size
        signature,              // signature
        signature_size);       // Signature size
    if (err_code != ERR_NONE) return err_code;
    
    return ERR_NONE;
}

/**@brief Add attest statement to CBOR Encoding. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
uint8_t ctap_add_attest_statement(CborEncoder * map, uint8_t * signature, int len)
{
    int ret;

    CborEncoder stmtmap;


    ret = cbor_encode_int(map,RESP_attStmt);
    if (ret != CborNoError) return ret;
    ret = cbor_encoder_create_map(map, &stmtmap, 2);
    if (ret != CborNoError) return ret;
    {
        ret = cbor_encode_text_stringz(&stmtmap,"alg");
        if (ret != CborNoError) return ret;
        ret = cbor_encode_int(&stmtmap,COSE_ALG_ES256);
        if (ret != CborNoError) return ret;
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"sig");
        if (ret != CborNoError) return ret;
        ret = cbor_encode_byte_string(&stmtmap, signature, len);
        if (ret != CborNoError) return ret;
    }

    ret = cbor_encoder_close_container(map, &stmtmap);
    if (ret != CborNoError) return ret;
    return ERR_NONE;
}

/**@brief Process CTAP_MAKE_CREDENTIAL request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
uint8_t ctap_make_credential(ctap_channel_t *p_ch)
{
    CTAP_makeCredential MC;
    int ret;
    
    uint32_t auth_data_sz = sizeof(CTAP_authData) + 100;    // authData + CBOR COSE_Key (around 77 bytes)
    uint8_t auth_data_buf[auth_data_sz];
    //CTAP_credentialDescriptor * excl_cred = (CTAP_credentialDescriptor *) auth_data_buf;
    
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));
    
    CTAP_RESPONSE ctap_resp;
    ctap_response_init(&ctap_resp);
    
    uint8_t * resp = ctap_resp.data;
    resp[0] = 0x00;    // First byte of buffer,Status response, 0x00 means success
    
    uint8_t * buf = resp + 1; // buf starts after first byte status response
    
    cbor_encoder_init(&encoder, buf, ctap_resp.data_size, 0);
    
    
    ret = ctap_parse_make_credential(&MC,&encoder,p_ch);
    
    if (ret != ERR_NONE)
    {
        ctap_hid_error_response(p_ch->cid, ret); return ret;
    }
    
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask)
    {
        ctap_hid_error_response(p_ch->cid, CTAP2_ERR_MISSING_PARAMETER);
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    
    if (MC.up)
    {
        ctap_hid_error_response(p_ch->cid, CTAP2_ERR_INVALID_OPTION);
        return CTAP2_ERR_INVALID_OPTION;
    }
    
    CborEncoder map;
    
    ret = cbor_encoder_create_map(&encoder, &map, 3);
    
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, CTAP2_ERR_INVALID_CBOR); return CTAP2_ERR_INVALID_CBOR; }
        ret = cbor_encode_text_stringz(&map, "packed");     // Packed Attestation Format: https://www.w3.org/TR/webauthn/#packed-attestation
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, CTAP2_ERR_INVALID_CBOR); return CTAP2_ERR_INVALID_CBOR; }
    }
    
    bsp_board_leds_off();
    bsp_board_led_on(GREEN_LED);
    while( !is_user_button_pressed() );     // USER PRESENCE REQUIRED HERE
    bsp_board_leds_off();
    
    nrf_crypto_ecc_private_key_t private_key;
    
    ret = ctap_make_auth_data(p_ch, &MC.rp, &map, auth_data_buf, &auth_data_sz, &MC.credInfo, &private_key);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    // Adding authData to CBOR response
    ret = cbor_encode_int(&map,RESP_authData);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    
    nrf_crypto_ecdsa_secp256r1_signature_t signature;
    size_t signature_size = sizeof(signature);
    
    ret = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, signature, &signature_size, &private_key);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    // Key deallocation
    ret = nrf_crypto_ecc_private_key_free(&private_key);
    if( ret != NRF_SUCCESS )
    {
        bsp_board_leds_off();
        blink_led_fast(RED_LED);
        ctap_hid_error_response(p_ch->cid, ret);
        return ret;
    }
    
    uint8_t signature_der[80];
    size_t signature_der_size;
    
    signature_der_size = signature_convert(signature_der,signature);
    //if(signature_der_size != ERR_NONE) { ctap_hid_error_response(p_ch->cid, signature_der_size); return signature_der_size; }
    
    ret = ctap_add_attest_statement(&map, signature_der, signature_der_size);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    ret = cbor_encoder_close_container(&encoder, &map);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    ctap_resp.length = cbor_encoder_get_buffer_size(&encoder, buf) + 1; // buff size + status response byte
    
    ret = ctap_hid_if_send(p_ch->cid, p_ch->cmd, ctap_resp.data, ctap_resp.length);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    //bsp_board_led_on(BLUE_LED);
    return ERR_NONE;
    //return ERR_NONE;
}

/**@brief Process CTAP_GET_ASSERTION request. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
uint8_t ctap_get_assertion(ctap_channel_t *p_ch)
{
    CTAP_getAssertion GA;
    int ret;
    
    uint32_t auth_data_sz = sizeof(CTAP_authDataHeader);    // authData without attestedCredential
    uint8_t auth_data_buf[auth_data_sz];
    
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));
    
    CTAP_RESPONSE ctap_resp;
    ctap_response_init(&ctap_resp);
    
    uint8_t * resp = ctap_resp.data;
    resp[0] = 0x00;    // First byte of buffer,Status response, 0x00 means success
    
    uint8_t * buf = resp + 1; // buf starts after first byte status response
    
    cbor_encoder_init(&encoder, buf, ctap_resp.data_size, 0);
    
    ret = ctap_parse_get_assertion(&GA,p_ch->req + 1,p_ch->bcnt);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    if (!GA.rp.size || !GA.clientDataHashPresent)
    {
        blink_led_fast(RED_LED);
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    
    if( GA.credLen == 0 )
    {
        blink_led_fast(RED_LED);
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    
    bsp_board_leds_off();
    bsp_board_led_on(GREEN_LED);
    bsp_board_led_on(RED_LED);
    while( !is_user_button_pressed() );     // USER PRESENCE REQUIRED HERE
    bsp_board_leds_off();
    
    m_auth_counter++;
    /* Write the updated record to flash. */
    ret = fds_record_update(&m_counter_record_desc, &m_counter_record);
    APP_ERROR_CHECK(ret);
    
    CborEncoder map;
    int map_size = 2;
    
    if(GA.credLen > 1)
        map_size++;

    ret = cbor_encoder_create_map(&encoder, &map, map_size);
    
    ret = ctap_make_auth_data(p_ch, &GA.rp, &map, auth_data_buf, &auth_data_sz, NULL, NULL);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    
    
    //blink_led_fast(GREEN_LED);
    
    nrf_crypto_ecc_private_key_t private_key;   // Private Key
    
    ret = ctap_recover_private_key(&GA.rp, GA.creds[0], &private_key);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    //blink_led_fast(YELLOW_LED);
    
    nrf_crypto_ecdsa_secp256r1_signature_t signature;
    size_t signature_size = sizeof(signature);
    
    ret = ctap_calculate_signature(auth_data_buf, auth_data_sz, GA.clientDataHash, signature, &signature_size, &private_key);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    uint8_t signature_der[80];
    size_t signature_der_size;
    
    signature_der_size = signature_convert(signature_der,signature);
    
    // Adding authData to CBOR response
    ret = cbor_encode_int(&map,RESP_authData);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    if(GA.credLen > 1)
    {
        // Adding credential to CBOR response
        ret = cbor_encode_int(&map,RESP_credential);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
        ret = cbor_encode_byte_string(&map, (uint8_t *)GA.creds[0], sizeof(CTAP_credentialDescriptor));
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    }
    
    // Adding credential to CBOR response
    ret = cbor_encode_int(&map,RESP_signature);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    ret = cbor_encode_byte_string(&map, signature_der, signature_der_size);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    ret = cbor_encoder_close_container(&encoder, &map);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    ctap_resp.length = cbor_encoder_get_buffer_size(&encoder, buf) + 1; // buff size + status response byte
    
    ret = ctap_hid_if_send(p_ch->cid, p_ch->cmd, ctap_resp.data, ctap_resp.length);
    if(ret != ERR_NONE) { ctap_hid_error_response(p_ch->cid, ret); return ret; }
    
    
    blink_led_fast(BLUE_LED);
    return ERR_NONE;
}

/**@brief Process CTAP_GET_INFO response. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
uint8_t ctap_get_info(ctap_channel_t *p_ch)
{
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));
    
    CTAP_RESPONSE ctap_resp;
    ctap_response_init(&ctap_resp);
    
    uint8_t * resp = ctap_resp.data;
    resp[0] = 0x00;    // First byte of buffer,Status response, 0x00 means success
    
    uint8_t * buf = resp + 1; // buf starts after first byte status response
    
    cbor_encoder_init(&encoder, buf, ctap_resp.data_size, 0);
    
    //bsp_board_leds_off();
    
    ret = cbor_encoder_create_map(&encoder, &map, 4);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
    
        ret = cbor_encode_uint(&map, RESP_versions);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
            ret = cbor_encoder_create_array(&map, &array, 1);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
            
                //ret = cbor_encode_text_stringz(&array, "U2F_V2");
                //if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
            
            ret = cbor_encoder_close_container(&map, &array);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
        ret = cbor_encode_uint(&map, RESP_aaguid);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
            ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
        ret = cbor_encode_uint(&map, RESP_options);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
            ret = cbor_encoder_create_map(&map, &options, 3);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
            
                ret = cbor_encode_text_string(&options, "rk", 2);
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_boolean(&options, 0);     // NOT capable of storing keys locally
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_text_string(&options, "up", 2);
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_boolean(&options, 1);     // Capable of testing user presence
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_text_string(&options, "plat", 4);
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
                
                ret = cbor_encode_boolean(&options, 0);     // Not attached to platform
                if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
            
            ret = cbor_encoder_close_container(&map, &options);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
        ret = cbor_encode_uint(&map, RESP_maxMsgSize);
        if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
            ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
            if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
        
    ret = cbor_encoder_close_container(&encoder, &map);
    if(ret != CborNoError) { ctap_hid_error_response(p_ch->cid, ERR_OTHER); return ERR_OTHER; }
    
    ctap_resp.length = cbor_encoder_get_buffer_size(&encoder, buf) + 1; // buff size + status response byte
    
    ret = ctap_hid_if_send(p_ch->cid, p_ch->cmd, ctap_resp.data, ctap_resp.length);
    
    
    if(ret == ERR_NONE)
        bsp_board_led_invert(GREEN_LED);
    else
        bsp_board_led_invert(RED_LED);
    
    return ERR_NONE;
}
