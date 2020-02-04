// Common CTAP HID transport header - Review Draft
// 2014-10-08
// Editor: Jakob Ehrensvard, Yubico, jakob@yubico.com

#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

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

// LED Definitions for blink functions
#define PWR_LED 0
#define RED_LED 1
#define GREEN_LED 2
#define BLUE_LED 3
#define CYAN_LED 4
#define MAGENTA_LED 5
#define YELLOW_LED 6
#define WHITE_LED 7

/**
 * @brief Blink a color led
 *
 * @param color     ID of color led
 * */
void blink_led(int color);

/**
 * @brief Blink slow a color led
 *
 * @param color     ID of color led
 * */
void blink_led_slow(int color);

/**
 * @brief Blink fast a color led
 *
 * @param color     ID of color led
 * */
void blink_led_fast(int color);

/**
 * @brief Blink n times a color led
 *
 * @param color     ID of color led
 * */
void blinkn_led(int color, int n);


#ifdef __cplusplus
}
#endif

#endif  // __CTAPHID_H_INCLUDED__
