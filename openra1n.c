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
#include <boot_pongo.h>

#include <common/log.h>

#include <getopt.h>

static int openFile(char *file, size_t *sz, void **buf)
{
    FILE *fd = fopen(file, "r");
    if (!fd)
    {
        printf("error opening %s\n", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf)
    {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}

static void usage(const char* arg0)
{
    printf("%s -k <Pongo.bin>\n", arg0);
}

int main(int argc, char **argv)
{
    
    int opt = 0;
    static struct option longopts[] =
    {
        { "help",               no_argument,       NULL, 'h' },
        { "override-pongo",     required_argument, NULL, 'k' },
        { NULL, 0, NULL, 0 }
    };
    
    const char* opt_str = "hk:";
    
    while ((opt = getopt_long(argc, argv, opt_str, longopts, NULL)) > 0)
    {
        switch (opt)
        {
            case 'h':
                usage(argv[0]);
                return 0;
                
            case 'k':
                if (optarg)
                {
                    if (openFile(optarg, &custom_pongo_len, &custom_pongo))
                    {
                        usage(argv[0]);
                        return -1;
                    }
                    if(custom_pongo_len > MAX_PONGOOS_RAW_SIZE)
                    {
                        printf("error: pongoOS too large\n");
                        return -1;
                    }
                }
                else
                {
                    usage(argv[0]);
                    return -1;
                }
                break;
                
            default:
                usage(argv[0]);
                return -1;
        }
    }
    
    LOG_RAINBOW("-=-=- openra1n -=-=-");
    int ret = EXIT_FAILURE;
    usb_handle_t handle;
    usb_timeout = 5;
    usb_abort_timeout_min = 0;
    LOG_INFO("Waiting for DFU mode device");
    do_openra1n(&handle);
    return ret;
}
