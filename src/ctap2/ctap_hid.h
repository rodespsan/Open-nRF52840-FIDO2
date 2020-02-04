// Common CTAP HID transport header - Review Draft
// 2014-10-08
// Editor: Jakob Ehrensvard, Yubico, jakob@yubico.com

#ifndef __CTAPHID_H_INCLUDED__
#define __CTAPHID_H_INCLUDED__

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

#include "ctap.h"
#include "timer_platform.h"
#include "timer_interface.h"

// Size of HID reports 

#define HID_RPT_SIZE            64      // Default size of raw HID report
    
// Frame layout - command- and continuation frames

#define CID_BROADCAST           0xffffffff // Broadcast channel id

#define TYPE_MASK               0x80    // Frame type mask 
#define TYPE_INIT               0x80    // Initial frame identifier
#define TYPE_CONT               0x00    // Continuation frame identifier

typedef struct {
  uint32_t cid;                        // Channel identifier
  union {
    uint8_t type;                      // Frame type - b7 defines type
    struct {
      uint8_t cmd;                     // Command - b7 set
      uint8_t bcnth;                   // Message byte count - high part
      uint8_t bcntl;                   // Message byte count - low part
      uint8_t data[HID_RPT_SIZE - 7];  // Data payload
    } init;
    struct {
      uint8_t seq;                     // Sequence number - b7 cleared
      uint8_t data[HID_RPT_SIZE - 5];  // Data payload
    } cont;
  };
} CTAPHID_FRAME;

#define MAX_INITIAL_PACKET      57
#define MAX_CONTINUATION_PACKET 59

#define FRAME_TYPE(f) ((f).type & TYPE_MASK)
#define FRAME_CMD(f)  ((f).init.cmd & ~TYPE_MASK)
#define MSG_LEN(f)    ((f).init.bcnth*256 + (f).init.bcntl)
#define FRAME_SEQ(f)  ((f).cont.seq & ~TYPE_MASK)

// HID usage- and usage-page definitions

#define FIDO_USAGE_PAGE         0xf1d0  // FIDO alliance HID usage page
#define FIDO_USAGE_CTAPHID      0x01    // CTAPHID usage for top-level collection
#define FIDO_USAGE_DATA_IN      0x20    // Raw IN data report
#define FIDO_USAGE_DATA_OUT     0x21    // Raw OUT data report
        
// General constants    

#define CTAPHID_IF_VERSION       2       // Current interface implementation version
#define CTAPHID_TRANS_TIMEOUT    3000    // Default message timeout in ms

#define CTAPHID_FW_VERSION_MAJOR 1       // Major version number
#define CTAPHID_FW_VERSION_MINOR 0       // Minor version number
#define CTAPHID_FW_VERSION_BUILD 0       // Build version number

// CTAPHID native commands

#define CTAPHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define CTAPHID_MSG          (TYPE_INIT | 0x03)  // Send CTAP message frame
#define CTAPHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define CTAPHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define CTAPHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define CTAPHID_CBOR         (TYPE_INIT | 0x10)  // Send a CTAP CBOR message frame
#define CTAPHID_CANCEL       (TYPE_INIT | 0x11)  // Cancel any outstanding requests on this CID
#define CTAPHID_SYNC         (TYPE_INIT | 0x3c)  // Protocol resync command
#define CTAPHID_KEEPALIVE    (TYPE_INIT | 0x3b)  // Keepalive command
#define CTAPHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define CTAPHID_VENDOR_FIRST (TYPE_INIT | 0x40)  // First vendor defined command
#define CTAPHID_VENDOR_LAST  (TYPE_INIT | 0x7f)  // Last vendor defined command
    
// CTAPHID_INIT command defines

#define INIT_NONCE_SIZE         8       // Size of channel initialization challenge

// CTAPHID Status responses, obtained from https://github.com/solokeys/solo/blob/master/fido2/ctaphid.h
#define CTAPHID_STATUS_IDLE         0
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

// CTAPHID_INIT Device capabilities flags
#define CAPABILITY_WINK            0x01    // Authenticator implements CTAPHID_WINK function
#define CAPABILITY_CBOR            0x04    // Authenticator implements CTAPHID_CBOR function
#define CAPABILITY_NMSG            0x08    // Athenticator DOES NOT implement CTAPHID_MSG function 



typedef struct __attribute__ ((__packed__)) {
  uint8_t nonce[INIT_NONCE_SIZE];       // Client application nonce
} CTAPHID_INIT_REQ;

typedef struct __attribute__ ((__packed__)) {
  uint8_t nonce[INIT_NONCE_SIZE];       // Client application nonce
  uint32_t cid;                         // Channel identifier  
  uint8_t versionInterface;             // CTAPHID protocol version identifier
  uint8_t versionMajor;                 // Major device version number
  uint8_t versionMinor;                 // Minor device version number
  uint8_t versionBuild;                 // Build device version number
  uint8_t capFlags;                     // Capabilities flags  
} CTAPHID_INIT_RESP;


// CTAPHID_SYNC command defines

typedef struct __attribute__ ((__packed__)) {
  uint8_t nonce;                        // Client application nonce
} CTAPHID_SYNC_REQ;

typedef struct __attribute__ ((__packed__)) {
  uint8_t nonce;                        // Client application nonce
} CTAPHID_SYNC_RESP;

// Low-level error codes. Return as negatives.

#define ERR_NONE                0x00    // No error
#define ERR_INVALID_CMD         0x01    // Invalid command
#define ERR_INVALID_PAR         0x02    // Invalid parameter
#define ERR_INVALID_LEN         0x03    // Invalid message length
#define ERR_INVALID_SEQ         0x04    // Invalid message sequencing
#define ERR_MSG_TIMEOUT         0x05    // Message has timed out
#define ERR_CHANNEL_BUSY        0x06    // Channel busy
#define ERR_LOCK_REQUIRED       0x0a    // Command requires channel lock
#define ERR_INVALID_CHANNEL     0x0b    // Command requires channel lock
#define ERR_SYNC_FAIL           0x0b    // SYNC command failed, replaced by ERR_INVALID_CHANNEL on CTAP2
#define ERR_OTHER               0x7f    // Other unspecified error

/**@brief Send a CTAPHID_ERROR response
 *
 * @param[in]  cid   Channel identifier.
 * @param[in]  code  Error code.
 * 
 */
void ctap_hid_error_response(uint32_t cid, uint8_t error);

/**
 * @brief Function for initializing the CTAP HID.
 *
 * @return Error status.
 *
 */
uint32_t ctap_hid_init(void);


/**
 * @brief CTAPHID process function, which should be executed when data is ready.
 *
 */
void ctap_hid_process(void);



#ifdef __cplusplus
}
#endif

#endif  // __CTAPHID_H_INCLUDED__
