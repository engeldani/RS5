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


    uint32_t antes_sw = csr_read_mcycle();

    uint64_t sub_keys[4] = {};
    uint64_t tmp1,tmp2;
    uint64_t c = 0xFFFFFFFFFFFFFFFC; 
    // Setup
    for(int i = 0; i < key_words; i++) {
        memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
    }

    // Store First Key Schedule Entry
    memcpy(cipher_object->key_schedule, &sub_keys[0], word_bytes);

    for (int i = 0; i < simon_rounds[cipher_cfg] - 1; i++) {
        tmp1 = rshift_three(sub_keys[key_words - 1]);

        if (key_words == 4) {
            tmp1 ^= sub_keys[1];
        }

        tmp2 = rshift_one(tmp1);
        tmp1 ^= sub_keys[0];
        tmp1 ^= tmp2;

        tmp2 = c ^ ((z_arrays[cipher_object->z_seq] >> (i % 62)) & 1);

        tmp1 ^= tmp2;

        // Shift Sub Words
        for (int j = 0; j < (key_words - 1); j++) {
            sub_keys[j] = sub_keys[j + 1];
        }
        sub_keys[key_words - 1] = tmp1 & mod_mask;

        // Append sub key to key schedule
        memcpy(cipher_object->key_schedule + (word_bytes * (i + 1)), &sub_keys[0], word_bytes);
    }

    uint32_t agora_sw = csr_read_mcycle();
    printf("Key schedule SW: %lu\n", (agora_sw-antes_sw));

    // COPIA DA CHAVE INICIAL PARA O HARDWARE
    uint32_t antes_hw = csr_read_mcycle();
    memcpy(&SIMON_KEY, key, 16);
    uint32_t agora_hw = csr_read_mcycle();
    printf("Key schedule hw; %lu\n", (agora_hw-antes_hw));
    // FIM DA COPIA    

    if(cipher_cfg <= cfg_256_128) {
        cipher_object->encryptPtr = Simon_Encrypt_128;
        cipher_object->decryptPtr = Simon_Decrypt_128;
    }

    else return 1;

    return 0;
}


uint8_t Simon_Encrypt(SimSpk_Cipher cipher_object, const void *plaintext, void *ciphertext) {
    (*cipher_object.encryptPtr)(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    return 0;
}

void Simon_Encrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                       uint8_t *ciphertext) {

    uint32_t antes = csr_read_mcycle();
    memcpy(&SIMON_PT, plaintext, 16);

    SIMON_CSR = 1; // start

    while((SIMON_CSR & 0x00000002) == 0); // aguarda

    memcpy(ciphertext, &SIMON_CT, 16);
    uint32_t agora = csr_read_mcycle();

    printf("Encrypt HW: %lu\n", (agora-antes));
}

uint8_t Simon_Decrypt(SimSpk_Cipher cipher_object, const void *ciphertext, void *plaintext) {
    (*cipher_object.decryptPtr)(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    return 0;
}

void Simon_Decrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                       uint8_t *plaintext){

    uint32_t antes = csr_read_mcycle();

    const uint8_t word_size = 64;
    uint64_t *x_word = (uint64_t *)plaintext;
    uint64_t *y_word = ((uint64_t *)plaintext) + 1;
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;

    *x_word = *(uint64_t *)ciphertext;
    *y_word = *(((uint64_t *)ciphertext) + 1);

    for(int8_t i = round_limit - 1; i >=0; i--) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);
        
        // Feistel Cross
        *y_word = *x_word;
        
        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
    
    uint32_t agora = csr_read_mcycle();
    printf("Decrypt SW: %lu\n", (agora-antes));
}
