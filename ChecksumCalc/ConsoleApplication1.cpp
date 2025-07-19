// validate_image.c
// Compile: gcc -std=c99 -O2 validate_image.c -o validate_image

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define EXTMEM_SIZE  0x10000
#define BANK_SIZE    0xC000

static uint8_t extmem[EXTMEM_SIZE];
static uint8_t* flash_data = NULL;
static size_t   flash_size = 0;

// ----------------------------------------------------------------------------
// EXTMEM accessors (big-endian for 32-bit)
// ----------------------------------------------------------------------------
static inline uint8_t  extRead8(uint32_t addr) {
    return (addr < EXTMEM_SIZE) ? extmem[addr] : 0;
}
static inline void     extWrite8(uint32_t addr, uint8_t  v) {
    if (addr < EXTMEM_SIZE) extmem[addr] = v;
}

static inline uint16_t extRead16(uint32_t addr) {
    if (addr + 1 < EXTMEM_SIZE) {
        return (extmem[addr] << 8) | extmem[addr + 1];
    }
    return 0;
}
static inline void     extWrite16(uint32_t addr, uint16_t v) {
    if (addr + 1 < EXTMEM_SIZE) {
        extmem[addr] = (v >> 8) & 0xFF;
        extmem[addr + 1] = (v) & 0xFF;
    }
}

static inline uint32_t extRead32(uint32_t addr) {
    if (addr + 3 < EXTMEM_SIZE) {
        return (extmem[addr] << 24) |
            (extmem[addr + 1] << 16) |
            (extmem[addr + 2] << 8) |
            (extmem[addr + 3]);
    }
    return 0;
}
static inline void     extWrite32(uint32_t addr, uint32_t v) {
    if (addr + 3 < EXTMEM_SIZE) {
        extmem[addr] = (v >> 24) & 0xFF;
        extmem[addr + 1] = (v >> 16) & 0xFF;
        extmem[addr + 2] = (v >> 8) & 0xFF;
        extmem[addr + 3] = (v) & 0xFF;
    }
}

// ----------------------------------------------------------------------------
// falshdata read/write for 8-bit, 16-bit, and 32-bit values   
// ----------------------------------------------------------------------------
static inline uint8_t  flashRead8(uint32_t addr) {
    return (addr < flash_size) ? flash_data[addr] : 0;
}
static inline void     flashWrite8(uint32_t addr, uint8_t  v) {
    if (addr < flash_size) flash_data[addr] = v;
}
static inline uint16_t flashRead16(uint32_t addr) {
    if (addr + 1 < flash_size) {
        return (flash_data[addr] << 8) | flash_data[addr + 1];
    }
    return 0;
}
static inline void     flashWrite16(uint32_t addr, uint16_t v) {
    if (addr + 1 < flash_size) {
        flash_data[addr] = (v >> 8) & 0xFF;
        flash_data[addr + 1] = (v) & 0xFF;
    }
}
static inline uint32_t flashRead32(uint32_t addr) {
    if (addr + 3 < flash_size) {
        return (flash_data[addr] << 24) |
            (flash_data[addr + 1] << 16) |
            (flash_data[addr + 2] << 8) |
            (flash_data[addr + 3]);
    }
    return 0;
}
static inline void     flashWrite32(uint32_t addr, uint32_t v) {
    if (addr + 3 < flash_size) {
        flash_data[addr] = (v >> 24) & 0xFF;
        flash_data[addr + 1] = (v >> 16) & 0xFF;
        flash_data[addr + 2] = (v >> 8) & 0xFF;
        flash_data[addr + 3] = (v) & 0xFF;
    }
}


// ----------------------------------------------------------------------------
// 8-bit carry/add and borrow/sub helpers
// ----------------------------------------------------------------------------
static inline uint8_t add8(uint8_t a, uint8_t b, uint8_t* carry_out) {
    uint16_t sum = (uint16_t)a + (uint16_t)b;
    *carry_out = (sum > 0xFF);
    return (uint8_t)sum;
}
static inline uint8_t sub8(uint8_t a, uint8_t b, uint8_t* borrow_out) {
    *borrow_out = (a < b);
    return (uint8_t)(a - b);
}

// ----------------------------------------------------------------------------
// Concatenate up to four bytes into a 32-bit word (MSB first)
// ----------------------------------------------------------------------------
static inline uint32_t concat4(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    return ((uint32_t)b0 << 24) |
        ((uint32_t)b1 << 16) |
        ((uint32_t)b2 << 8) |
        ((uint32_t)b3);
}

// ----------------------------------------------------------------------------
// Bank‐switched CRC routine from your C routine
// ----------------------------------------------------------------------------
static uint8_t calculate_bank_crc(uint32_t param_len) {
    // Initialize EXTMEM regs for CRC
    extWrite32(0xE00, param_len);
    extWrite32(0xE04, 0);
    extWrite8(0xE05, 0);
    extWrite8(0xE06, 0);
    extWrite8(0xE07, 0);

    int BANK_REGISTER = 2;

    // Phase 1: process 0x4000‐byte banks until length ≥ 0xC000
    while (extRead32(0xE00) < 0xC000) {
        uint32_t stored_crc = 0;
        uint32_t ptr = BANK_REGISTER * BANK_SIZE + 0x4000;

        // inner loop: build 32-bit counter from bytes
        while ((ptr >> 8) != 0) {
            uint32_t counter = 0;
            do {
                uint8_t C3 = (counter >> 24) & 0xFF;
                uint8_t C2 = (counter >> 16) & 0xFF;
                uint8_t b
                    = (ptr < flash_size) ? flash_data[ptr] : 0;
                ptr++;

                uint8_t c1, c2;
                uint8_t s1 = add8(b, C3, &c1);
                uint8_t s2 = add8(C2, c1, &c2);
                uint8_t rd = ((counter >> 8) & 0xFF) - 1;

                counter = (((uint32_t)s1 << 16) |
                    ((uint32_t)s2 << 8) |
                    (uint32_t)rd) << 8;
            } while (((counter >> 8) & 0xFF) != 0);

            // fold counter bytes [31:8] into stored_crc
            uint8_t crc3 = (stored_crc >> 24) & 0xFF;
            uint8_t crc2 = (stored_crc >> 16) & 0xFF;
            uint8_t crc1 = (stored_crc >> 8) & 0xFF;
            uint8_t A = (counter >> 24) & 0xFF;
            uint8_t B = (counter >> 16) & 0xFF;
            uint8_t C = (counter >> 8) & 0xFF;

            uint8_t carry;
            uint8_t tA = add8(A, crc3, &carry);
            uint8_t dB = sub8(B, carry, &carry);
            uint8_t tB = add8(dB, crc2, &carry);
            uint8_t dC = sub8(C, carry, &carry);
            uint8_t tC = (crc1 + dC) & 0xFF;

            stored_crc = ((uint32_t)tA << 24) |
                ((uint32_t)tB << 16) |
                ((uint32_t)tC << 8);
        }

        // accumulate into E07/E06/E05/E04
        uint8_t b4 = (stored_crc >> 24) & 0xFF;
        uint8_t b5 = (stored_crc >> 16) & 0xFF;
        uint8_t b6 = (stored_crc >> 8) & 0xFF;

        uint8_t c;
        uint8_t s = add8(extRead8(0xE07), b4, &c);
        extWrite8(0xE07, s);

        uint8_t d = sub8(b5, c, &c);
        s = add8(extRead8(0xE06), d, &c);
        extWrite8(0xE06, s);

        d = sub8(b6, c, &c);
        s = add8(extRead8(0xE05), d, &c);
        extWrite8(0xE05, s);

        extWrite8(0xE04, (extRead8(0xE04) - c) & 0xFF);

        BANK_REGISTER++;

        printf("✅ BANK_REGISTER=0x%08X\n", BANK_REGISTER);

        // increment length in E00 by 0x40 on low‐order byte
        uint32_t L = extRead32(0xE00);
        uint8_t  b1 = (L >> 8) & 0xFF;
        uint8_t  b2 = (L >> 16) & 0xFF;
        uint8_t  b3 = (L >> 24) & 0xFF;
        uint8_t  flag = (b1 < 0xC0);

        uint8_t nb0 = (b3 + ((b2 < (0x100 - flag)) ? 1 : 0)) & 0xFF;
        uint8_t nb1 = (b2 + flag) & 0xFF;
        uint8_t nb2 = (b1 + 0x40) & 0xFF;
        uint8_t nb3 = L & 0xFF;

        extWrite32(0xE00, concat4(nb0, nb1, nb2, nb3));
    }

    // Phase 2: final pass
    uint32_t stored_crc = ((extRead8(0xE03) << 8) | extRead8(0xE02)) << 16;
    uint32_t uVar3 = concat4(
        extRead8(0xE07), extRead8(0xE06),
        extRead8(0xE05), extRead8(0xE04)
    );
    int bank2 = BANK_REGISTER * BANK_SIZE + 0x4000;

    while (1) {
        uint8_t C3 = (stored_crc >> 24) & 0xFF;
        uint8_t C2 = (stored_crc >> 16) & 0xFF;
        if (C3 == 0 && C2 == 0) break;

        // decrement be [C3:C2]
        C3 = C3 - 1;
        stored_crc = (stored_crc & 0x00FFFFFF) | (C3 << 24);
        if (C3 == 0xFF) {
            C2 = C2 - 1;
            stored_crc = (stored_crc & 0xFF00FFFF) | (C2 << 16);
        }

        uint8_t b = (bank2 < (int)flash_size) ? flash_data[bank2] : 0;
        bank2++;

        uint8_t t0, t1, c0;
        t0 = add8(b, (uVar3 >> 24) & 0xFF, &c0);
        t1 = sub8((uVar3 >> 16) & 0xFF, c0, &c0);
        uint8_t t2 = (uVar3 >> 8) & 0xFF;
        uint8_t t3 = uVar3 & 0xFF;
        uVar3 = concat4(t0, t1, t2, t3);
    }

    return extRead8(0xE04);
}

// ----------------------------------------------------------------------------
// Stubbed hardware‐specific routines
// ----------------------------------------------------------------------------
static void load_magic_vals(void) {
    // TODO: implement if needed
}

static bool validate_magic_number(uint32_t ptr) {
    // TODO: implement real check
    (void)ptr;
    return true;
}

uint32_t corrected_crc_length(uint32_t length) {
    // Decompose into bytes
    uint8_t b0 = length & 0xFF;
    uint8_t b1 = (length >> 8) & 0xFF;
    uint8_t b2 = (length >> 16) & 0xFF;
    uint8_t b3 = (length >> 24) & 0xFF;

    // Apply staged corrections
    uint8_t c1 = 0xD0 - (b0 > 0xFD);
    uint8_t b1_sum = b1 + c1;
    uint8_t c2 = 0xFF - ((b1_sum & 0xFF) < b1);
    uint8_t b2_sum = b2 + c2;
    uint8_t c3 = -1 - ((b2_sum & 0xFF) < b2);
    uint8_t b3_sum = b3 + c3;

    // Final correction word
    return (b3_sum << 24) | (b2_sum << 16) | (b1_sum << 8) | (b0 + 2);
}



// ----------------------------------------------------------------------------
// Top‐level image validation
// ----------------------------------------------------------------------------
static void validate_image(bool start_kernel) {
    // 1) Magic
    load_magic_vals();
    if (!validate_magic_number(0x5E1601)) {
        printf("Magic check failed. Header error.\n");
        return;
    }

    // Load 0x1D000..0x1d014 into extmem 165E..1672
    for (uint32_t i = 0; i < 0x14; i++) {
        extWrite8(0x165E + i, flashRead8(0x1D000 + i));
    }


    // 2) Runtime checksum CODE[0x1000..0x3FFE]
    extWrite8(0xDFA, 0);
    extWrite32(0xDFE, 0x1000);
    extWrite32(0xDE6, 0);
    while (extRead16(0xDFA) < 0x2FFE) {
        uint32_t suma = extRead32(0xDE6);
        uint32_t off = extRead32(0xDFE);
        uint8_t  b = (off < flash_size) ? flash_data[off] : 0;
        extWrite32(0xDE6, suma + b);
        extWrite16(0xDFA, extRead16(0xDFA) + 1);
        extWrite32(0xDFE, off + 1);
    }
    printf("✅ Runtime checksum: 0x%08X\n", extRead32(0xDE6));

    // 3) Header-bytes checksum CODE[0x5E16 .. +0x14]
    extWrite32(0xDF2, extRead32(0xDE6));
    extWrite32(0xDF6, 0);
    extWrite16(0xDFC, 0x165E);
    extWrite8(0xDFA, 0);
    while (extRead8(0xDFA) < 0x14) {
        uint32_t addr = extRead16(0xDFC);
        uint8_t  hv = (addr < flash_size) ? flash_data[addr] : 0;
        uint8_t  delta = (0x100 - hv - 1) & 0xFF;
        extWrite32(0xDF6, extRead32(0xDF6) + delta);
        extWrite16(0xDFC, addr + 1);
        extWrite8(0xDFA, extRead8(0xDFA) + 1);
    }
    printf("✅ Header checksum: 0x%08X\n", extRead32(0xDF6));

    uint32_t header_len = extRead32(0x1662);
    uint32_t payload_chk = extRead32(0x166A);

    printf("✅ Header length: 0x%08X\n", header_len);
    printf("✅ Payload checksum: 0x%08X\n", payload_chk);

    // 5) Final header checksum word
    uint32_t hdr_chk = corrected_crc_length(header_len);

    extWrite32(0xDEE, hdr_chk);
    printf("✅ subchk: 0x%08X\n", hdr_chk);

    // 6) Combine sub-bytes checksum + bank CRC
    uint32_t subchk = extRead32(0xDF6);
    //uint8_t  bkcrc = calculate_bank_crc(extRead32(0xDEE));
    uint8_t  bkcrc = calculate_bank_crc(0x000DE8A2);
    extWrite32(0xDF6, subchk + bkcrc);

    printf("✅ subchk: 0x%08X\n", subchk);
    printf("✅ bkcrc: 0x%08X\n", bkcrc);

    // 7) Final runtime + payload compare
    uint32_t total = extRead32(0xDE6) + extRead32(0xDF6);
    if (total == payload_chk) {
        printf("✅ Image valid (0x%08X)\n", total);
        if (start_kernel) {
            printf("▶️ Jumping to runtime at 0x1000\n");
        }
    }
    else {
        printf("❌ Checksum mismatch: 0x%08X != 0x%08X\n",
            total, payload_chk);
    }
}

// ----------------------------------------------------------------------------
// Main: load firmware and invoke validate_image()
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <startKernel:0|1> <firmware.bin>\n", argv[0]);
        return 1;
    }
    bool start_kernel = (argv[1][0] != '0');

    // load firmware
    FILE* f = NULL;
    if (fopen_s(&f, argv[2], "rb") != 0) {
        perror("fopen_s");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    flash_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    flash_data = (uint8_t*)malloc(flash_size);
    if (!flash_data) {
        perror("malloc");
        return 1;
    }
    if (fread(flash_data, 1, flash_size, f) != flash_size) {
        perror("fread");
        return 1;
    }
    fclose(f);

    // clear EXTMEM
    memset(extmem, 0, sizeof(extmem));

    printf("✅ Loaded firmware: %s (%zu bytes)\n", argv[2], flash_size);
    // run validation
    validate_image(start_kernel);

    free(flash_data);
    return 0;
}
