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
#include "util.h"


/**
 * @brief Invert a color led RGB-CYM
 *
 * @param color     ID of color led
 * */
void led_invert(int color)
{
    switch(color)
    {
        case PWR_LED: 
        case RED_LED: 
        case GREEN_LED: 
        case BLUE_LED: 
            bsp_board_led_invert(color); 
            break;
        case CYAN_LED: 
            bsp_board_led_invert(GREEN_LED); 
            bsp_board_led_invert(BLUE_LED); 
            break;
        case MAGENTA_LED: 
            bsp_board_led_invert(RED_LED); 
            bsp_board_led_invert(BLUE_LED); 
            break;
        case YELLOW_LED: 
            bsp_board_led_invert(RED_LED); 
            bsp_board_led_invert(GREEN_LED); 
            break;
        case WHITE_LED: 
            bsp_board_led_invert(RED_LED); 
            bsp_board_led_invert(GREEN_LED); 
            bsp_board_led_invert(BLUE_LED); 
            break;
    }
}

/**
 * @brief Blink a color led
 *
 * @param color     ID of color led
 * */
void blink_led(int color)
{
    for(int i=1; i<9; i++){
        bsp_board_led_invert(color);
        nrf_delay_ms(500);
    }
}

/**
 * @brief Blink slow a color led
 *
 * @param color     ID of color led
 * */
void blink_led_slow(int color)
{
    for(int i=1; i<5; i++){
        bsp_board_led_invert(color);
        nrf_delay_ms(2000);
    }
}

/**
 * @brief Blink fast a color led
 *
 * @param color     ID of color led
 * */
void blink_led_fast(int color)
{
    bsp_board_leds_off();
    for(int i=1; i<15; i++){
        led_invert(color);
        nrf_delay_ms(100);
    }
}

/**
 * @brief Blink n times a color led
 *
 * @param color     ID of color led
 * */
void blinkn_led(int color, int n)
{
    bsp_board_leds_off();
    for(int i=0; i<n; i++){
        led_invert(color);
        nrf_delay_ms(500);
        led_invert(color);
        nrf_delay_ms(500);
    }
}

