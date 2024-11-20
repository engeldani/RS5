#pragma once

#include <stdint.h>

#define SIMON_PT    (*((volatile uint32_t*)0x40000000))
#define SIMON_PT_LL (*((volatile uint32_t*)0x40000000))
#define SIMON_PT_LH (*((volatile uint32_t*)0x40000004))
#define SIMON_PT_HL (*((volatile uint32_t*)0x40000008))
#define SIMON_PT_HH (*((volatile uint32_t*)0x4000000C))

#define SIMON_KEY    (*((volatile uint32_t*)0x40000010))
#define SIMON_KEY_LL (*((volatile uint32_t*)0x40000010))
#define SIMON_KEY_LH (*((volatile uint32_t*)0x40000014))
#define SIMON_KEY_HL (*((volatile uint32_t*)0x40000018))
#define SIMON_KEY_HH (*((volatile uint32_t*)0x4000001C))

#define SIMON_CT    (*((volatile uint32_t*)0x40000020))
#define SIMON_CT_LL (*((volatile uint32_t*)0x40000020))
#define SIMON_CT_LH (*((volatile uint32_t*)0x40000024))
#define SIMON_CT_HL (*((volatile uint32_t*)0x40000028))
#define SIMON_CT_HH (*((volatile uint32_t*)0x4000002C))

#define SIMON_CSR   (*((volatile uint32_t*)0x40000030))

#define SIMON_MODE  (*((volatile uint32_t*)0x40000034))
