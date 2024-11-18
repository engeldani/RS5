/*
 * tests.c
 * Tests For Simon and Speck Block Ciphers
 * Copyright 2017 Michael Calvin McCoy
 * calvin.mccoy@gmail.com
 * # The MIT License (MIT) - see LICENSE.md
*/

#include <stdio.h>
#include <stdint.h>
#include "simon.h"

// Function Prototypes
void cipher_compare(const void *source, void *target, size_t n);

// Global Test count
int test_count = 0;

// Global Fail count
int fail_count = 0;


void cipher_compare(const void *source, void *target, size_t n) {
    test_count++;
    for(size_t i=0; i < n; i++) {
        uint8_t * src_bytes = (uint8_t *)source;
        uint8_t * trg_bytes = (uint8_t *)target;
        printf("Byte %02zu: %02x - %02x",i, src_bytes[i], trg_bytes[i]);
        if (src_bytes[i] != trg_bytes[i]) {
            printf("  FAIL\n");
            fail_count++;
        }
        else printf("\n");
    }
}

int main(void){

    // Create reusable cipher objects for each algorithm type
    SimSpk_Cipher my_simon_cipher;

    // Create generic tmp variables
    uint8_t ciphertext_buffer[16];
    uint32_t result;

    // Initialize IV and Counter Values for Use with Block Modes
    uint8_t my_IV[] = {0x32,0x14,0x76,0x58};
    uint8_t my_counter[] = {0x2F,0x3D,0x5C,0x7B};

    printf("***********************************\n");
    printf("******* Simon Cipher Tests ********\n");
    printf("***********************************\n");

    // Simon 128/128 Test
    // Key: 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 6373656420737265 6c6c657661727420 Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
    printf("**** Test Simon 128/128 ****\n");
    uint8_t simon128_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06,0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t simon128_128_plain[] = {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63};
    uint8_t simon128_128_cipher[] = {0xbc, 0x0b, 0x4e, 0xf8, 0x2a, 0x83, 0xaa, 0x65, 0x3f, 0xfe, 0x54, 0x1e, 0x1e, 0x1b, 0x68, 0x49};
    result = Simon_Init(&my_simon_cipher, cfg_128_128, ECB, simon128_128_key, my_IV, my_counter);
    if (result != 0) {
        printf("Error initializing simon: %lu\n", result);
        return result;
    }
    printf("Encryption Test:\n");
    Simon_Encrypt(my_simon_cipher, &simon128_128_plain, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_128_cipher, sizeof(simon128_128_cipher));

    printf("Decryption Test:\n");
    Simon_Decrypt(my_simon_cipher, &simon128_128_cipher, &ciphertext_buffer);
    cipher_compare(&ciphertext_buffer, &simon128_128_plain, sizeof(simon128_128_plain));

    printf("\n");

    printf("Total Test Count: %d\n", test_count);
    printf("Total Fail Count: %d\n", fail_count);

    return fail_count;
}
