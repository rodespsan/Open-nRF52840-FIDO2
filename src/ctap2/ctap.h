// Common CTAP raw message format header - Review Draft
// 2014-10-08
// Editor: Jakob Ehrensvard, Yubico, jakob@yubico.com

#ifndef __CTAP_H_INCLUDED__
#define __CTAP_H_INCLUDED__

#ifdef _MSC_VER  // Windows
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned int      uint32_t;
typedef unsigned long int uint64_t;
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "cbor.h"
#include "ctap_hid.h"
#include "timer_platform.h"
#include "timer_interface.h"

/* File ID and Key used for the configuration record. */
#define CONFIG_AES_KEY_FILE     (0xEF10)
#define CONFIG_AES_KEY_REC_KEY  (0x7F10)

/* File ID and Key used for the configuration record. */
#define CONFIG_COUNTER_FILE     (0xEF11)
#define CONFIG_COUNTER_REC_KEY  (0x7F11)

#define AES_KEY_SIZE             16

// General constants

#define CTAP_EC_KEY_SIZE         32      // EC key size in bytes
#define CTAP_EC_POINT_SIZE       ((CTAP_EC_KEY_SIZE * 2) + 1) // Size of EC point
#define CTAP_MAX_KH_SIZE         128     // Max size of key handle
#define CTAP_MAX_ATT_CERT_SIZE   2048    // Max size of attestation certificate
#define CTAP_MAX_EC_SIG_SIZE     72      // Max size of DER coded EC signature
#define CTAP_CTR_SIZE            4       // Size of counter field
#define CTAP_APPID_SIZE          32      // Size of application id
#define CTAP_CHAL_SIZE           32      // Size of challenge

#define ENC_SIZE(x)             ((x + 7) & 0xfff8)


// EC (uncompressed) point

#define CTAP_POINT_UNCOMPRESSED  0x04    // Uncompressed point format

typedef struct __attribute__ ((__packed__)) {
    uint8_t pointFormat;                // Point type
    uint8_t x[CTAP_EC_KEY_SIZE];         // X-value
    uint8_t y[CTAP_EC_KEY_SIZE];         // Y-value
} CTAP_EC_POINT;

// CTAP1 native commands

#define CTAP_REGISTER            0x01    // Registration command
#define CTAP_AUTHENTICATE        0x02    // Authenticate/sign command
#define CTAP_VERSION             0x03    // Read version string command
#define CTAP_CHECK_REGISTER      0x04    // Registration command that incorporates checking key handles
#define CTAP_AUTHENTICATE_BATCH  0x05    // Authenticate/sign command for a batch of key handles

//#define CTAP_VENDOR_FIRST        0xc0    // First vendor defined command
//#define CTAP_VENDOR_LAST         0xff    // Last vendor defined command

// CTAP2 native commands, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define CTAP_MAKE_CREDENTIAL        0x01    // Generate new credential in the authenticator
#define CTAP_GET_ASSERTION          0x02    // Proof of user authentication as well as user consent
#define CTAP_CANCEL                 0x03    
#define CTAP_GET_INFO               0x04    // Report supported protocol versions, extensions, AAGUID and capabilities
#define CTAP_CLIENT_PIN             0x06    // Sends PIN in encrypted format
#define CTAP_RESET                  0x07    // Reset an authenticator back to a factory default state
#define GET_NEXT_ASSERTION          0x08    // Obtain the next per-credential signature

#define CTAP_VENDOR_FIRST           0x40    // First vendor defined command
#define CTAP_VENDOR_LAST            0xBF    // Last vendor defined command

// AAGUID For CTAP2UoB, example obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h and generated from https://www.random.org/bytes/ 
#define CTAP_AAGUID                 ((uint8_t*)"\xe6\x77\xce\x6a\x86\x3e\x5e\xff\x28\x0e\x75\xcc\xbf\x1f\x99\x73")

// CTAP2 makeCredential parameter keys, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define MC_clientDataHash         0x01
#define MC_rp                     0x02
#define MC_user                   0x03
#define MC_pubKeyCredParams       0x04
#define MC_excludeList            0x05
#define MC_extensions             0x06
#define MC_options                0x07
#define MC_pinAuth                0x08
#define MC_pinProtocol            0x09

// CTAP2 getAssertion parameter keys, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define GA_rpId                   0x01
#define GA_clientDataHash         0x02
#define GA_allowList              0x03
#define GA_extensions             0x04
#define GA_options                0x05
#define GA_pinAuth                0x06
#define GA_pinProtocol            0x07

// Response Keys for authenticatorGetInfo_Response, obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define RESP_versions               0x1
#define RESP_extensions             0x2
#define RESP_aaguid                 0x3
#define RESP_options                0x4
#define RESP_maxMsgSize             0x5
#define RESP_pinProtocols           0x6

// CTAP2 response keys for authenticatorMakeCredential response, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define RESP_fmt                    0x01
#define RESP_authData               0x02
#define RESP_attStmt                0x03

// CTAP2 response keys for authenticatorGetAssertion response, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define RESP_credential             0x01
#define RESP_signature              0x03
#define RESP_publicKeyCredentialUserEntity 0x04
#define RESP_numberOfCredentials    0x05

// CTAP2 authenticatorMakeCredential parameter masks, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define PARAM_clientDataHash        (1 << 0)
#define PARAM_rp                    (1 << 1)
#define PARAM_user                  (1 << 2)
#define PARAM_pubKeyCredParams      (1 << 3)
#define PARAM_excludeList           (1 << 4)
#define PARAM_extensions            (1 << 5)
#define PARAM_options               (1 << 6)
#define PARAM_pinAuth               (1 << 7)
#define PARAM_pinProtocol           (1 << 8)
#define PARAM_rpId                  (1 << 9)
#define PARAM_allowList             (1 << 10)

// Mask showing that required params were processed for MakeCredential, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define MC_requiredMask             (0x0f)

// CTAP2 static definitions, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define CLIENT_DATA_HASH_SIZE       32  //sha256 hash
#define DOMAIN_NAME_MAX_SIZE        253
#define RP_NAME_LIMIT               32  // application limit, name parameter isn't needed.
#define USER_ID_MAX_SIZE            64
#define USER_NAME_LIMIT             65  // Must be minimum of 64 bytes but can be more.
#define DISPLAY_NAME_LIMIT          32  // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT                  128 // Must be minimum of 64 bytes but can be more.
#define CTAP_MAX_MESSAGE_SIZE       1200

// CTAP2 static definitions for CredentialID, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define CREDENTIAL_RK_FLASH_PAD     2   // size of RK should be 8-byte aligned to store in flash easily.
#define CREDENTIAL_TAG_SIZE         16
//#define CREDENTIAL_NONCE_SIZE       (16 + CREDENTIAL_RK_FLASH_PAD)
#define CREDENTIAL_NONCE_SIZE       16
#define CREDENTIAL_COUNTER_SIZE     (4)
#define CREDENTIAL_ENC_SIZE         176  // pad to multiple of 16 bytes

// CTAP2 Public Key Types, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define PUB_KEY_CRED_PUB_KEY        0x01
#define PUB_KEY_CRED_CTAP1          0x41
#define PUB_KEY_CRED_CUSTOM         0x42
#define PUB_KEY_CRED_UNKNOWN        0x3F

// CREDENTIAL IS/NOT SUPPORTED, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define CREDENTIAL_IS_SUPPORTED     1
#define CREDENTIAL_NOT_SUPPORTED    0

// ALLOW_LIST_MAX_SIZE, obtained from: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define ALLOW_LIST_MAX_SIZE         20

// CTAP_CMD_REGISTER command defines

#define CTAP_REGISTER_ID         0x05    // Version 2 registration identifier
#define CTAP_REGISTER_HASH_ID    0x00    // Version 2 hash identintifier

typedef struct __attribute__ ((__packed__)) {
    uint8_t chal[CTAP_CHAL_SIZE];        // Challenge
    uint8_t appId[CTAP_APPID_SIZE];      // Application id
} CTAP_REGISTER_REQ;

typedef struct __attribute__ ((__packed__)) {
    uint8_t registerId;                 // Registration identifier (CTAP_REGISTER_ID_V2)
    CTAP_EC_POINT pubKey;                // Generated public key
    uint8_t keyHandleLen;               // Length of key handle
    uint8_t keyHandleCertSig[
        CTAP_MAX_KH_SIZE +               // Key handle
        CTAP_MAX_ATT_CERT_SIZE +         // Attestation certificate
        CTAP_MAX_EC_SIG_SIZE];           // Registration signature
} CTAP_REGISTER_RESP;

// CTAP_CMD_AUTHENTICATE command defines

// Authentication control byte

#define CTAP_AUTH_ENFORCE        0x03    // Enforce user presence and sign
#define CTAP_AUTH_CHECK_ONLY     0x07    // Check only
#define CTAP_AUTH_FLAG_TUP       0x01    // Test of user presence set

typedef struct __attribute__ ((__packed__)) {
    uint8_t chal[CTAP_CHAL_SIZE];        // Challenge
    uint8_t appId[CTAP_APPID_SIZE];      // Application id
    uint8_t keyHandleLen;               // Length of key handle
    uint8_t keyHandle[CTAP_MAX_KH_SIZE]; // Key handle
} CTAP_AUTHENTICATE_REQ;

typedef struct __attribute__ ((__packed__)) {
    uint8_t flags;                      // CTAP_AUTH_FLAG_ values
    uint8_t ctr[CTAP_CTR_SIZE];          // Counter field (big-endian)
    uint8_t sig[CTAP_MAX_EC_SIG_SIZE];   // Signature
} CTAP_AUTHENTICATE_RESP;


#define CTAP_MAX_REQ_SIZE        (sizeof(CTAP_AUTHENTICATE_REQ) + 10)
#define CTAP_MAX_RESP_SIZE       (sizeof(CTAP_REGISTER_RESP) + 2)

typedef struct { struct ctap_channel *pFirst, *pLast; } ctap_channel_list_t;

typedef struct ctap_channel {
    struct ctap_channel * pPrev;
    struct ctap_channel * pNext;
    uint32_t cid;
    uint8_t cmd;
    uint8_t state;
    Timer timer;
    uint16_t bcnt;
    uint8_t req[CTAP_MAX_MESSAGE_SIZE];
    uint8_t resp[CTAP_MAX_RESP_SIZE];
} ctap_channel_t;

typedef struct __attribute__ ((__packed__))
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc1;
    uint8_t lc2;
    uint8_t lc3;
} ctap_req_apdu_header_t;

// Command status responses

#define CTAP_SW_NO_ERROR                 0x9000 // SW_NO_ERROR
#define CTAP_SW_WRONG_LENGTH             0x6700 // SW_WRONG_LENGTH
#define CTAP_SW_WRONG_DATA               0x6A80 // SW_WRONG_DATA
#define CTAP_SW_CONDITIONS_NOT_SATISFIED 0x6985 // SW_CONDITIONS_NOT_SATISFIED
#define CTAP_SW_COMMAND_NOT_ALLOWED      0x6986 // SW_COMMAND_NOT_ALLOWED
#define CTAP_SW_INS_NOT_SUPPORTED        0x6D00 // SW_INS_NOT_SUPPORTED
#define CTAP_SW_CLA_NOT_SUPPORTED        0x6E00 // SW_CLA_NOT_SUPPORTED

#define VENDOR_CTAP_NOMEM                0xEE04
#define VENDOR_CTAP_VERSION              "CTAP_V2"

// Struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
#define CTAP_RESPONSE_BUFFER_SIZE   4096

#define CTAP_CREDENTIAL_SOURCE_SIZE 351

// CTAP2 Public Key Credential Source. For more details: https://www.w3.org/TR/webauthn/#public-key-credential-source
typedef struct
{
    uint8_t iv[AES_KEY_SIZE];                                 // IV (nonce+counter) when Credential Source is encrypted
    uint8_t type;                               // Default "public-type", we use PUB_KEY_CRED_PUB_KEY=0x01 constant
    uint8_t privateKey[CTAP_EC_KEY_SIZE];       // Private Key in raw format
    uint8_t rpId[DOMAIN_NAME_MAX_SIZE + 1];     // Relying Party ID
    uint8_t userHandle[USER_ID_MAX_SIZE];       // User handle specified by Relying Party, same as user.id
} __attribute__((packed)) CTAP_credentialSource;    // Size = 1 + 32 + 254 + 64 = 351

// CTAP User Entity struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t id[USER_ID_MAX_SIZE];
    uint8_t id_size;
    uint8_t name[USER_NAME_LIMIT];
    uint8_t displayName[DISPLAY_NAME_LIMIT];
    uint8_t icon[ICON_LIMIT];
}__attribute__((packed)) CTAP_userEntity;

// CTAP2 credentialID struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct {
    uint8_t tag[CREDENTIAL_TAG_SIZE];
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
    uint8_t rpIdHash[32];
    uint32_t count;
}__attribute__((packed)) CredentialId;

// CTAP2 residentKey struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
struct Credential {
    CTAP_credentialSource id;
    CTAP_userEntity user;
};
typedef struct Credential CTAP_residentKey;

// CTAP2 Credential Descriptor struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t type;
    struct Credential credential;
} CTAP_credentialDescriptor;

// CTAP2 attestHeader struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t aaguid[16];
    uint8_t credLenH;
    uint8_t credLenL;
    CTAP_credentialSource credentialId;
    //CredentialId id;
} __attribute__((packed)) CTAP_attestHeader;

// CTAP2 authDataHeader struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t rpIdHash[32];
    uint8_t flags;
    uint32_t signCount;
} __attribute__((packed)) CTAP_authDataHeader;

// CTAP2 authData struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    CTAP_authDataHeader head;
    CTAP_attestHeader attest;
} __attribute__((packed)) CTAP_authData;

// CTAP2 Response struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
    uint16_t data_size;
    uint16_t length;
} CTAP_RESPONSE;

// Rely Party ID struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
struct rpId
{
    uint8_t id[DOMAIN_NAME_MAX_SIZE + 1];     // extra for NULL termination
    size_t size;
    uint8_t name[RP_NAME_LIMIT];
};

// COSE key params struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    struct{
        uint8_t x[32];
        uint8_t y[32];
    } pubkey;

    int kty;
    int crv;
} COSE_key;

// HMAC extension struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t saltLen;
    uint8_t saltEnc[64];
    uint8_t saltAuth[32];
    COSE_key keyAgreement;
    struct Credential * credential;
} CTAP_hmac_secret;

// CTAP extensions struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;
} CTAP_extensions;

// CTAP Credential Info struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    CTAP_userEntity user;
    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;
    uint8_t rk;
} CTAP_credInfo;

// Struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    struct rpId rp;

    CTAP_credInfo credInfo;

    CborValue excludeList;
    size_t excludeListSize;

    uint8_t uv;
    uint8_t up;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    // pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
    // This is exclusive with |pinAuthPresent|. It exists because an empty
    // pinAuth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
    uint8_t pinAuthEmpty;
    int pinProtocol;
    CTAP_extensions extensions;

} CTAP_makeCredential;

// Struct definition obtained from https://github.com/solokeys/solo/blob/master/fido2/ctap.h
typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    uint8_t clientDataHashPresent;

    struct rpId rp;

    int credLen;

    uint8_t rk;
    uint8_t uv;
    uint8_t up;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    // pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
    // This is exclusive with |pinAuthPresent|. It exists because an empty
    // pinAuth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorGetAssertion
    uint8_t pinAuthEmpty;
    int pinProtocol;

    CTAP_credentialDescriptor * creds[ALLOW_LIST_MAX_SIZE];
    uint8_t allowListPresent;

    CTAP_extensions extensions;

} CTAP_getAssertion;


/**
 * @brief Function for initializing the CTAP implementation.
 *
 * @return Error status.
 *
 */
uint32_t ctap_impl_init(void);


/**
 * @brief Register CTAP Key.
 *
 *
 * @param[in] p_req          Registration Request Message.
 * @param[out] p_resp        Registration Response Message.
 * @param[in] flags          Request Parameter.
 * @param[out] p_resp_len    Registration Response Message length
 *
 * @return Standard error code.
 */
uint16_t ctap_register(CTAP_REGISTER_REQ * p_req, CTAP_REGISTER_RESP * p_resp, 
                      int flags, uint16_t * p_resp_len);


/**
 * @brief CTAP Key Authentication.
 *
 *
 * @param[in] p_req          Authentication Request Message.
 * @param[out] p_resp        Authentication Response Message.
 * @param[in] flags          Request Parameter.
 * @param[out] p_resp_len    Authentication Response Message length
 *
 * @return Standard error code.
 */
uint16_t ctap_authenticate(CTAP_AUTHENTICATE_REQ * p_req, 
                          CTAP_AUTHENTICATE_RESP * p_resp, 
                          int flags, uint16_t * p_resp_len);
                          
uint8_t ctap_make_credential(ctap_channel_t *p_ch);

uint8_t ctap_get_assertion(ctap_channel_t *p_ch);

uint8_t ctap_get_info(ctap_channel_t *p_ch);

#ifdef __cplusplus
}
#endif

#endif  // __CTAP_H_INCLUDED__
