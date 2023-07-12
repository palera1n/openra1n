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

#include <openra1n_usb.h>
#include <common.h>
#include <checkm8.h>

#include <common/log.h>

int main(int argc, char **argv)
{
    LOG_RAINBOW("-=-=- openra1n -=-=-");
    int ret = EXIT_FAILURE;
    usb_handle_t handle;
    usb_timeout = 5;
    usb_abort_timeout_min = 0;
    LOG_INFO("Waiting for DFU mode device");
    checkm8(&handle);
    sleep_ms(3000);
    checkm8_boot_pongo(&handle);
    return ret;
}
