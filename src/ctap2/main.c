/**
 * Copyright (c) 2014 - 2019, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdbool.h>
#include <stdint.h>

#include "app_button.h"
#include "app_error.h"
#include "app_timer.h"
#include "app_usbd.h"
#include "app_usbd_hid_generic.h"
#include "app_usbd_hid_mouse.h"
#include "app_util.h"
#include "app_util_platform.h"
#include "boards.h"
#include "bsp.h"
#include "mem_manager.h"
#include "nrf_crypto.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"
#include "timer_interface.h"

#include "ctap_hid_if.h"
#include "ctap_hid.h"

#include "util.h"

#define LED_USB_RESUME (BSP_BOARD_LED_0)

/**
 * @brief Enable USB power detection
 */
#ifndef USBD_POWER_DETECTION
#define USBD_POWER_DETECTION true
#endif

/** SysTick counter to avoid busy wait delay. */
volatile uint32_t ms_ticks = 0;

/** CTAP user button state. */
static bool m_user_button_pressed = false;

/**
 * @brief Timer to repeat mouse move
 */
APP_TIMER_DEF(button_press_timer);

static void button_press_timer_handler(void * p_context)
{
    UNUSED_PARAMETER(p_context);
    /*bool used = false;

    if (bsp_button_is_pressed(0))
    {
        bsp_board_led_on(1);
        used = true;
    }
    if (bsp_button_is_pressed(1))
    {
        bsp_board_led_on(3);
        used = true;
    }

    if(!used)
    {
        UNUSED_RETURN_VALUE(app_timer_stop(button_press_timer));
    }*/
}

/**
 * \brief Check user button state. 
 */
bool is_user_button_pressed(void)
{
    if(m_user_button_pressed)
    {
        m_user_button_pressed = false;
        return true;
    }
    return false;
}

static void bsp_event_callback(bsp_event_t ev)
{
    //bsp_board_leds_off();
    
    switch(ev)
    {
        case BSP_EVENT_KEY_0: 
            if (bsp_button_is_pressed(0))
            {
                //bsp_board_led_invert(2);
            }
            else
            {
                m_user_button_pressed = true;
                //bsp_board_led_invert(3);
            }
            break;
        default:
            //bsp_board_led_invert(1);
            break;
    }
}

static void init_bsp(void)
{
    ret_code_t ret;
    ret = bsp_init(BSP_INIT_BUTTONS, bsp_event_callback);
    APP_ERROR_CHECK(ret);

    //INIT_BSP_ASSIGN_RELEASE_ACTION(BTN_MOUSE_LEFT );
    //INIT_BSP_ASSIGN_RELEASE_ACTION(BTN_MOUSE_RIGHT);
    ret = bsp_event_to_button_action_assign(0, BSP_BUTTON_ACTION_RELEASE, BSP_EVENT_KEY_0);
    APP_ERROR_CHECK(ret);

    /* Configure LEDs */
    bsp_board_init(BSP_INIT_LEDS);
}


/**
 * @brief Function for application main entry.
 */
int main(void)
{
    ret_code_t ret;
    
    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);
    
    nrf_drv_clock_lfclk_request(NULL);
    
    while(!nrf_drv_clock_lfclk_is_running())
    {
        /* Just waiting */
    }
    
    ret = app_timer_init();
    APP_ERROR_CHECK(ret);
    
    ret = app_timer_create(&button_press_timer, APP_TIMER_MODE_REPEATED, button_press_timer_handler);
    APP_ERROR_CHECK(ret);
    
    init_bsp();
    
    ret = ctap_hid_init();
    if(ret != NRF_SUCCESS)
    {
        blink_led_fast(RED_LED);
    }
    APP_ERROR_CHECK(ret);
    
    
    while (true)
    {
        ctap_hid_process();
        
        //bsp_board_led_invert(PWR_LED);
        //nrf_delay_ms(400);
    }
}

/**
 *@}
 **/
