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
#include "nrf_delay.h"
#include "app_util_platform.h"
#include "bsp.h"

#include "ctap.h"
#include "ctap_hid.h"
#include "ctap_hid_if.h"
#include "ctap_errors.h"
#include "cose_key.h"

#include "util.h"

#include "cbor.h"

#include "mem_manager.h"
#include "timer_interface.h"

#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_hash.h"
#include "nrf_crypto_error.h"

#define NRF_LOG_MODULE_NAME ctap_hid

#include "nrf_log.h"

NRF_LOG_MODULE_REGISTER();

#define MAX_CTAP_CHANNELS    5

#define CID_STATE_IDLE      1
#define CID_STATE_READY     2


extern bool is_user_button_pressed(void);


/**
 * @brief List of channels.
 *
 */
ctap_channel_list_t m_ctap_ch_list = {NULL, NULL};


/**
 * @brief The count of channel used.
 *
 */
static uint8_t m_channel_used_cnt = 0;

uint8_t ctap_get_info(ctap_channel_t *p_ch);

uint8_t ctap_make_credential(ctap_channel_t *p_ch);


/**@brief CTAP Channel allocation function.
 *
 *
 * @retval    Valid memory location if the procedure was successful, else, NULL.
 */
static ctap_channel_t * ctap_channel_alloc(void)
{
    ctap_channel_t * p_ch;
    size_t size = sizeof(ctap_channel_t);

    if(m_channel_used_cnt > MAX_CTAP_CHANNELS)
    {
        NRF_LOG_WARNING("MAX_CTAP_CHANNELS.");
        return NULL;
    }

    p_ch = nrf_malloc(size);
    if(p_ch == NULL)
    {
        NRF_LOG_ERROR("nrf_malloc: Invalid memory location!");
    }
    else
    {
        m_channel_used_cnt++;       
    }

    return p_ch;
}


/**@brief Initialize CTAP Channel.
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * @param[in]  cid   Channel identifier.
 *
 */
static void ctap_channel_init(ctap_channel_t * p_ch, uint32_t cid)
{
    size_t size = sizeof(ctap_channel_t);

    memset(p_ch, 0, size);

    p_ch->cid = cid;
    p_ch->state = CID_STATE_IDLE;
    p_ch->pPrev = NULL;
    p_ch->pNext = NULL;

    if(m_ctap_ch_list.pFirst == NULL)
    {
        m_ctap_ch_list.pFirst = m_ctap_ch_list.pLast = p_ch;
    }
    else
    {
        p_ch->pPrev = m_ctap_ch_list.pLast;
        m_ctap_ch_list.pLast->pNext = p_ch;
        m_ctap_ch_list.pLast = p_ch;
    }
}


/**@brief Uninitialize CTAP Channel.
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 *
 */
static void ctap_channel_deinit(ctap_channel_t * p_ch)
{
    if(p_ch->pPrev == NULL && p_ch->pNext == NULL)  //only one item in the list
    {
        m_ctap_ch_list.pFirst = m_ctap_ch_list.pLast = NULL;
    }
    else if(p_ch->pPrev == NULL)  // the first item
    {
        m_ctap_ch_list.pFirst = p_ch->pNext;
        p_ch->pNext->pPrev = NULL;
    }
    else if(p_ch->pNext == NULL) // the last item
    {
        m_ctap_ch_list.pLast = p_ch->pPrev;
        p_ch->pPrev->pNext = NULL;
    }
    else
    {
        p_ch->pPrev->pNext = p_ch->pNext;
        p_ch->pNext->pPrev = p_ch->pPrev;
    }
    nrf_free(p_ch);
    m_channel_used_cnt--;
}


/**@brief Find the CTAP Channel by cid.
 *
 * @param[in]  cid  Channel identifier.
 *
 * @retval     Valid CTAP Channel if the procedure was successful, else, NULL.
 */
static ctap_channel_t * ctap_channel_find(uint32_t cid)
{
    
    ctap_channel_t *p_ch;

    for(p_ch = m_ctap_ch_list.pFirst; p_ch != NULL; p_ch = p_ch->pNext)
    {
        if(p_ch->cid == cid)
        {
            return p_ch;
        }
    }

    return NULL;
}


/**@brief Generate new CTAP Channel identifier.
 *
 *
 * @retval     New Channel identifier.
 */
static uint32_t generate_new_cid(void)
{
    static uint32_t cid = 0;
    do
    {
        cid++;
    }while(cid == 0 || cid == CID_BROADCAST);
    return cid;
}


/**@brief Send a CTAPHID_ERROR response
 *
 * @param[in]  cid   Channel identifier.
 * @param[in]  code  Error code.
 * 
 */
void ctap_hid_error_response(uint32_t cid, uint8_t error)
{
    ctap_hid_if_send(cid, CTAPHID_ERROR, &error, 1);
}


/**@brief Handle a CTAPHID INIT response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_init_response(ctap_channel_t *p_ch)
{
    CTAPHID_INIT_RESP *p_resp_init = (CTAPHID_INIT_RESP *)p_ch->resp;
    
    ctap_channel_t *p_new_ch;

    if (p_ch->cid != CID_BROADCAST) {
         ctap_hid_error_response(p_ch->cid, ERR_INVALID_CMD);
         return;
    }

    p_new_ch = ctap_channel_alloc();
    if (p_new_ch == NULL) {
         ctap_hid_error_response(p_ch->cid, ERR_CHANNEL_BUSY);
         return;
    }

    ctap_channel_init(p_new_ch, generate_new_cid());

    memcpy(p_resp_init->nonce, p_ch->req, INIT_NONCE_SIZE); // Client application nonce

    p_resp_init->cid = p_new_ch->cid;                       // Channel identifier 
    p_resp_init->versionInterface = CTAPHID_IF_VERSION;     // CTAPHID protocol version identifier
    p_resp_init->versionMajor = CTAPHID_FW_VERSION_MAJOR;   // Major device version number
    p_resp_init->versionMinor = CTAPHID_FW_VERSION_MINOR;   // Minor device version number
    p_resp_init->versionBuild = CTAPHID_FW_VERSION_BUILD;   // Build device version number
    p_resp_init->capFlags = CAPABILITY_WINK | CAPABILITY_CBOR; // Capabilities flags 

    UNUSED_RETURN_VALUE(is_user_button_pressed());    // clear user button state

    ctap_hid_if_send(p_ch->cid, p_ch->cmd, (uint8_t *)p_resp_init, 
                    sizeof(CTAPHID_INIT_RESP));
}


/**@brief Handle a CTAPHID WINK response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_wink_response(ctap_channel_t *p_ch)
{
    bsp_board_led_invert(LED_CTAP_WINK);
    ctap_hid_if_send(p_ch->cid, p_ch->cmd, NULL, 0);
}

/**@brief Handle a CTAPHID_CBOR response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_cbor_response(ctap_channel_t *p_ch)
{
    uint8_t *ctapcmd = (uint8_t *)p_ch->req;
    
    switch(*ctapcmd)
    {
        case CTAP_MAKE_CREDENTIAL:
        {
            ctap_make_credential(p_ch);
        }
        break;
        
        case CTAP_GET_ASSERTION:
        {
            ctap_get_assertion(p_ch);
        }
        break;
        case CTAP_CANCEL:
        {
            
        }
        break;
        
        case CTAP_GET_INFO:
        {
            //bsp_board_led_invert(1);
            ctap_get_info(p_ch);
        }
        break;
        
        case CTAP_CLIENT_PIN:
        {
            
        }
        break;
        
        case CTAP_RESET:
        {
            
        }
        break;
        
        case GET_NEXT_ASSERTION:
        {
            
        }
        break;
        
        default:
        {
            ctap_hid_error_response(p_ch->cid, ERR_INVALID_CMD);
        }
        break;
    }
}

/**@brief Handle a CTAPHID_CANCEL response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_cancel_response(ctap_channel_t *p_ch)
{
    bsp_board_led_on(2);
    // TO DO
}


/**@brief Send a CTAP HID status code only
 *
 * @param[in]  p_ch    Pointer to CTAP Channel.
 * @param[in]  status  CTAP HID status code.
 *
 */
static void ctap_hid_status_response(ctap_channel_t * p_ch, uint16_t status)
{
    uint8_t be_status[2];
    uint8_t size = uint16_big_encode(status, be_status);

    ctap_hid_if_send(p_ch->cid, p_ch->cmd, be_status, size);
}


/**@brief Handle a CTAPHID MESSAGE response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_msg_response(ctap_channel_t * p_ch)
{
    ctap_req_apdu_header_t * p_req_apdu_hdr = (ctap_req_apdu_header_t *)p_ch->req;

    uint32_t req_size;

    if(p_req_apdu_hdr->cla != 0)
    {
        ctap_hid_status_response(p_ch, CTAP_SW_CLA_NOT_SUPPORTED);
        return;
    }

    req_size = (((uint32_t)p_req_apdu_hdr->lc1) << 16) |
               (((uint32_t)p_req_apdu_hdr->lc2) << 8)  |
               (((uint32_t)p_req_apdu_hdr->lc3) << 0);

    switch(p_req_apdu_hdr->ins)
    {
        case CTAP_REGISTER:
        {
            CTAP_REGISTER_REQ *p_req = (CTAP_REGISTER_REQ *)(p_req_apdu_hdr + 1);
            CTAP_REGISTER_RESP *p_resp = (CTAP_REGISTER_RESP *)p_ch->resp;

            if(req_size != sizeof(CTAP_REGISTER_REQ))
            {
                NRF_LOG_ERROR("CTAP_SW_WRONG_LENGTH.");
                ctap_hid_status_response(p_ch, CTAP_SW_WRONG_LENGTH);
                return;                 
            }

            uint16_t status, len = 0;
            uint8_t be_status[2];

            status = ctap_register(p_req, p_resp, p_req_apdu_hdr->p1, &len);

            if(status == CTAP_SW_CONDITIONS_NOT_SATISFIED)
            {
                NRF_LOG_WARNING("Press to register the device now...");
            }
            else if(status != CTAP_SW_NO_ERROR)
            {
                NRF_LOG_ERROR("Fail to register your device! [status = %d]", status);
            }
            else
            {
                NRF_LOG_INFO("Register your device successfully!");
            }

            uint8_t size = uint16_big_encode(status, be_status);

            memcpy(p_ch->resp + len, be_status, size);

            ctap_hid_if_send(p_ch->cid, p_ch->cmd, p_ch->resp, len + size);

        }
        break;

        case CTAP_AUTHENTICATE:
        {
            CTAP_AUTHENTICATE_REQ *p_req = (CTAP_AUTHENTICATE_REQ *)(p_req_apdu_hdr + 1);
            CTAP_AUTHENTICATE_RESP *p_resp = (CTAP_AUTHENTICATE_RESP *)p_ch->resp;

            if(req_size > sizeof(CTAP_AUTHENTICATE_REQ))
            {
                NRF_LOG_ERROR("Invalid request size: %d", req_size);
                ctap_hid_status_response(p_ch, CTAP_SW_WRONG_LENGTH);
                return;                 
            }

            uint16_t status, len = 0;
            uint8_t be_status[2];

            status = ctap_authenticate(p_req, p_resp, p_req_apdu_hdr->p1, &len);

            if(status == CTAP_SW_CONDITIONS_NOT_SATISFIED)
            {
                NRF_LOG_WARNING("Press to authenticate your device now...");
            }
            else if(status != CTAP_SW_NO_ERROR)
            {
                NRF_LOG_ERROR("Fail to authenticate your device! [status = %d]", status);
            }
            else
            {
                NRF_LOG_INFO("Authenticate your device successfully!");
            }

            uint8_t size = uint16_big_encode(status, be_status);
            
            memcpy(p_ch->resp + len, be_status, size);

            ctap_hid_if_send(p_ch->cid, p_ch->cmd, p_ch->resp, len + size);    
        }
        break;

        case CTAP_VERSION:
        {
            const char *ver_str = VENDOR_CTAP_VERSION;
            uint8_t len = strlen(ver_str);

            NRF_LOG_INFO("CTAP_VERSION.");

            if(req_size > 0)
            {
                ctap_hid_status_response(p_ch, CTAP_SW_WRONG_LENGTH);
               return;                 
            }

            uint8_t be_status[2];
            uint8_t size = uint16_big_encode(CTAP_SW_NO_ERROR, be_status);
            memcpy(p_ch->resp, ver_str, len);
            memcpy(p_ch->resp + len, be_status, size);

            ctap_hid_if_send(p_ch->cid, p_ch->cmd, p_ch->resp, len + size);
        }
        break;

        case CTAP_CHECK_REGISTER:
            break;

        case CTAP_AUTHENTICATE_BATCH:
            break;

        default:
            NRF_LOG_ERROR("CTAP_SW_INS_NOT_SUPPORTED.");
            ctap_hid_status_response(p_ch, CTAP_SW_INS_NOT_SUPPORTED);
            break;
    }
}

/**@brief Handle a CTAPHID PING response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_ping_response(ctap_channel_t *p_ch)
{
    ctap_hid_if_send(p_ch->cid, p_ch->cmd, p_ch->req, p_ch->bcnt);
}


/**@brief Handle a CTAPHID SYNC response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_sync_response(ctap_channel_t *p_ch)
{
	return;
}


/**@brief Handle a CTAPHID LOCK response
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_hid_lock_response(ctap_channel_t *p_ch)
{
	return;
}


/**@brief Process CTAPHID command
 *
 * @param[in]  p_ch  Pointer to CTAP Channel.
 * 
 */
static void ctap_channel_cmd_process(ctap_channel_t * p_ch)
{
    /*bsp_board_leds_off();
    blink_led_fast(BLUE_LED);
    bsp_board_leds_off();*/
    
    countdown_ms(&p_ch->timer, CTAPHID_TRANS_TIMEOUT);

    if(p_ch->state != CID_STATE_READY) return;

    switch(p_ch->cmd)
    {
        case CTAPHID_PING:
            NRF_LOG_INFO("CTAPHID_PING.");
            ctap_hid_ping_response(p_ch);
            break;

        case CTAPHID_MSG:
            NRF_LOG_INFO("CTAPHID_MSG.");
            ctap_hid_msg_response(p_ch);
            break;

        case CTAPHID_LOCK:
            NRF_LOG_INFO("CTAPHID_LOCK.");
            ctap_hid_lock_response(p_ch);
            break;

        case CTAPHID_INIT:
            NRF_LOG_INFO("CTAPHID_INIT.");
            ctap_hid_init_response(p_ch);
            break;

        case CTAPHID_WINK:
            NRF_LOG_INFO("CTAPHID_WINK.");
            ctap_hid_wink_response(p_ch);
            break;
        
        case CTAPHID_CBOR:
            NRF_LOG_INFO("CTAPHID_CBOR.");
            ctap_hid_cbor_response(p_ch);
            break;
            
        case CTAPHID_CANCEL:
            NRF_LOG_INFO("CTAPHID_CANCEL.");
            ctap_hid_cancel_response(p_ch);
            break;

        case CTAPHID_SYNC:
            NRF_LOG_INFO("CTAPHID_SYNC.");
            ctap_hid_sync_response(p_ch);
            break;
        
        case CTAPHID_VENDOR_FIRST:
            NRF_LOG_INFO("CTAPHID_VENDOR_FIRST.");
            break;

        case CTAPHID_VENDOR_LAST:
            NRF_LOG_INFO("CTAPHID_VENDOR_LAST.");
            break;

        default:
            NRF_LOG_WARNING("Unknown Command: %d", p_ch->cmd);
            break;
    }

    p_ch->state = CID_STATE_IDLE;
}

/**@brief Process CTAPHID command of every ready channel.
 * 
 */
static void ctap_channel_process(void)
{
    ctap_channel_t *p_ch;

    for(p_ch = m_ctap_ch_list.pFirst; p_ch != NULL;)
    {
        
        // Transaction timeout, free the channel
        if(has_timer_expired(&p_ch->timer) && p_ch->state == CID_STATE_IDLE)
        {
            if(p_ch->cid != CID_BROADCAST)
            {
                ctap_channel_t * p_free_ch = p_ch;
                p_ch = p_ch->pNext;
                ctap_channel_deinit(p_free_ch);
                continue;
            }
        }
        p_ch = p_ch->pNext;
    }
}


/**
 * @brief Function for initializing the CTAP HID.
 *
 * @return Error status.
 *
 */
ret_code_t ctap_hid_init(void)
{
    ret_code_t ret;
    ctap_channel_t *p_ch;

    ret = nrf_mem_init();
    if(ret != NRF_SUCCESS)
    {
        return ret;
    }

    ret = ctap_hid_if_init();
    if(ret != NRF_SUCCESS)
    {
    	return ret;
    }

    ret = ctap_impl_init();
    if(ret != NRF_SUCCESS)
    {
    	return ret;
    }

    p_ch = ctap_channel_alloc();
    if(p_ch == NULL)
    {
        NRF_LOG_ERROR("NRF_ERROR_NULL!");
        return NRF_ERROR_NULL;
    }

    ctap_channel_init(p_ch, CID_BROADCAST);

    return NRF_SUCCESS;
}



/**
 * @brief CTAPHID process function, which should be executed when data is ready.
 *
 */
void ctap_hid_process(void)
{
    uint8_t ret;
    uint32_t cid;
    uint8_t cmd;
    size_t size;
    uint8_t buf[CTAP_MAX_MESSAGE_SIZE];

    ctap_hid_if_process();

    ret = ctap_hid_if_recv(&cid, &cmd, buf, &size, 1000);

    if(ret == ERR_NONE)
    {
        ctap_channel_t * p_ch;

        p_ch = ctap_channel_find(cid);

        if(p_ch == NULL)
        {
            NRF_LOG_ERROR("No valid channel found!");
            ctap_hid_error_response(cid, ERR_CHANNEL_BUSY);
        }
        else
        {
            p_ch->cmd = cmd;
            p_ch->bcnt = size;
            p_ch->state = CID_STATE_READY;
            memcpy(p_ch->req, buf, size);
            ctap_channel_cmd_process(p_ch);
        }
    }

    ctap_channel_process();
}







/**@brief Creates a COSE Key for authenticatorMakeCredential Response. Based on code from:
 * https://github.com/solokeys/solo/blob/master/fido2/ctap.c
 *
 * @retval     ERR_NONE on sucess, ERROR on fail.
 *
 */
/*static int ctap_generate_cose_key(CborEncoder * cose_key, uint8_t * hmac_input, int len, uint8_t credtype, int32_t algtype)
{
    //uint8_t x[32], y[32];

    if (credtype != PUB_KEY_CRED_PUB_KEY)
    {
        blink_led_fast(RED_LED);
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    switch(algtype)
    {
        case COSE_ALG_ES256:
            blink_led_fast(BLUE_LED);
            //crypto_ecc256_derive_public_key(hmac_input, len, x, y);
            break;
        default:
            blink_led_fast(GREEN_LED);
            //printf2(TAG_ERR,"Error, COSE alg %d not supported\n", algtype);
            return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    //int ret = ctap_add_cose_key(cose_key, x, y, credtype, algtype);
    //check_ret(ret);
    return ERR_NONE;
}*/


