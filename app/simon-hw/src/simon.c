/*
 * Simon.c
 * Implementation of NSA Simon Block Cipher
 * Copyright 2017 Michael Calvin McCoy
 * calvin.mccoy@gmail.com
 *  # The MIT License (MIT) - see LICENSE.md
*/

#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "simon.h"
#include <riscv-csr.h>

#include "simon_registers.h"

// Cipher Operation Macros
#define shift_one(x_word) (((x_word) << 1) | ((x_word) >> (word_size - 1)))
#define shift_eight(x_word) (((x_word) << 8) | ((x_word) >> (word_size - 8)))
#define shift_two(x_word) (((x_word) << 2) | ((x_word) >> (word_size - 2)))

#define rshift_three(x) (((x) >> 3) | (((x) & 0x7) << (word_size - 3)))
#define rshift_one(x)   (((x) >> 1) | (((x) & 0x1) << (word_size - 1)))

uint64_t z_arrays[5] = {0b0001100111000011010100100010111110110011100001101010010001011111,
                        0b0001011010000110010011111011100010101101000011001001111101110001,
                        0b0011001101101001111110001000010100011001001011000000111011110101,
                        0b0011110000101100111001010001001000000111101001100011010111011011,
                        0b0011110111001001010011000011101000000100011011010110011110001011};

// Valid Cipher Parameters
const uint8_t simon_rounds[] = {32, 36, 36, 42, 44, 52, 54, 68, 69, 72};
const uint8_t  z_assign[] = {0, 0, 1, 2, 3, 2, 3, 2, 3, 4};

uint8_t Simon_Init(SimSpk_Cipher *cipher_object, enum cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter) {

    if (cipher_cfg > cfg_256_128 || cipher_cfg < cfg_64_32){
        return 1;
    }
    
    cipher_object->block_size = block_sizes[cipher_cfg];
    cipher_object->key_size = key_sizes[cipher_cfg];
    cipher_object->round_limit = simon_rounds[cipher_cfg];
    cipher_object->cipher_cfg = cipher_cfg;
    cipher_object->z_seq = z_assign[cipher_cfg];
    uint8_t word_size = block_sizes[cipher_cfg] >> 1;
    uint8_t word_bytes = word_size >> 3;
    uint16_t key_words =  key_sizes[cipher_cfg] / word_size;
    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);

    // COPIA DA CHAVE INICIAL PARA O HARDWARE
    uint32_t antes = csr_read_mcycle();
    memcpy(&SIMON_KEY, key, 16);
    uint32_t agora = csr_read_mcycle();
    printf("Key schedule HW; %lu\n", (agora-antes));
    // FIM DA COPIA    

    if(cipher_cfg <= cfg_256_128) {
        cipher_object->encryptPtr = Simon_Encrypt_128;
        cipher_object->decryptPtr = Simon_Decrypt_128;
    }

    else return 1;

    return 0;
}


uint8_t Simon_Encrypt(SimSpk_Cipher cipher_object, const void *plaintext, void *ciphertext) {
    (*cipher_object.encryptPtr)(cipher_object.round_limit, plaintext, ciphertext);
    return 0;
}

void Simon_Encrypt_128(const uint8_t round_limit, const uint8_t *plaintext,
                       uint8_t *ciphertext) {

    uint32_t antes = csr_read_mcycle();
    SIMON_MODE = 1;
    memcpy(&SIMON_PT, plaintext, 16);

    SIMON_CSR = 1; // start

    while((SIMON_CSR & 0x00000002) == 0); // aguarda

    memcpy(ciphertext, &SIMON_CT, 16);
    uint32_t agora = csr_read_mcycle();

    printf("Encrypt HW: %lu\n", (agora-antes));
}

uint8_t Simon_Decrypt(SimSpk_Cipher cipher_object, const void *ciphertext, void *plaintext) {
    (*cipher_object.decryptPtr)(cipher_object.round_limit, ciphertext, plaintext);
    return 0;
}

void Simon_Decrypt_128(const uint8_t round_limit, const uint8_t *ciphertext,
                       uint8_t *plaintext){
    
    uint32_t antes = csr_read_mcycle();
    SIMON_MODE = 0;
    memcpy(&SIMON_PT, ciphertext, 16);

    SIMON_CSR = 1; // start

    while((SIMON_CSR & 0x00000002) == 0); // aguarda

    memcpy(plaintext, &SIMON_CT, 16);
    uint32_t agora = csr_read_mcycle();

    printf("Decrypt HW: %lu\n", (agora-antes));
}
