#ifndef PAYLOADS_H
#define PAYLOADS_H
#include <stdint.h>

#if !defined(OPENRA1N_INTERNAL)
extern uint8_t s8000_bin[], s8001_bin[], s8003_bin[], t7000_bin[], t7001_bin[], t8010_bin[], t8011_bin[], t8012_bin[], t8015_bin[];
extern unsigned int s8000_bin_len, s8001_bin_len, s8003_bin_len, t7000_bin_len, t7001_bin_len, t8010_bin_len, t8011_bin_len, t8012_bin_len, t8015_bin_len;

extern uint8_t Pongo_bin[];
extern unsigned int pongo_bin_len;
#endif

extern uint8_t lz4dec_bin[];
extern unsigned int lz4dec_bin_len;
#endif
