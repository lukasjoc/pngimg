#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

// Converts a byte array to an uint32_t
#define into_u32(bytes) (uint32_t)((bytes[0] << 24) + (bytes[1] << 16) \
        + (bytes[2] << 8) + bytes[3])

/* Table of CRCs of all 8-bit messages. */
uint32_t crc_table[256];

/* Flag: has the table been computed? Initially false. */
int crc_table_computed = 0;

/* Make the table for a fast CRC. */
void make_crc_table(void) {
    uint32_t c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = (uint32_t) n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}


/* Update a running CRC with the bytes buf[0..len-1]--the CRC
   should be initialized to all 1's, and the transmitted value
   is the 1's complement of the final running CRC (see the
   crc() routine below). */

uint32_t update_crc(uint32_t crc, unsigned char *buf,
        int len) {
    uint32_t c = crc;
    int n;

    if (!crc_table_computed)
        make_crc_table();
    for (n = 0; n < len; n++) {
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
uint32_t crc(unsigned char *buf, int len) {
    return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

//size_t concat_byte_arrays(uint8_t *dest, const void *a, const void *b, size_t size_a, size_t size_b) {
//    memcpy(dest, a, sizeof(*a));
//    memcpy(dest, b, sizeof(*b));
//    return size_dest;
//}

int main (void) {
    unsigned char sample_crc[4] = { 99,51,45,219 };

    const int BYTE_BOUNDARY = 4;
    const int DATA_LENGTH_MAX = 1024*32;
    int read_data_length = 2639;
    unsigned char sample_type[BYTE_BOUNDARY] = {105,67,67,80};
    unsigned char sample_data[DATA_LENGTH_MAX] = {
80,104,111,116,111,115,104,111,112,32,73,67,67,32,112,114,111,102,105,108,101,0,0,120,218,157,83,103,84,83,233,22,61,247,222,244,66,75,136,128,148,75,111,82,21,8,32,82,66,139,128,20,145,38,42,33,9,16,74,136,33,161,217,21,81,193,17,69,69,4,27,200,160,136,3,142,142,128,140,21,81,44,12,138,10,216,7,228,33,162,142,131,163,136,138,202,251,225,123,163,107,214,188,247,230,205,254,181,215,62,231,172,243,157,179,207,7,192,8,12,150,72,51,81,53,128,12,169,66,30,17,224,131,199,196,198,225,228,46,64,129,10,36,112,0,16,8,179,100,33,115,253,35,1,0,248,126,60,60,43,34,192,7,190,0,1,120,211,11,8,0,192,77,155,192,48,28,135,
    };

    uint8_t sample_crc_payload[DATA_LENGTH_MAX + BYTE_BOUNDARY] = {0};
    memcpy(sample_crc_payload, sample_type, sizeof(sample_type));
    memcpy(sample_crc_payload+sizeof(sample_type), sample_data, sizeof(sample_data));

    // size_t bytes_copied = concat_byte_arrays(sample_crc_payload, (const void*)sample_type, (const void*)sample_data);


    unsigned char length[4] = {79, 10, 0, 0}; //{0,0,10,79};
    printf("l: =%u \n", into_u32(length));
    printf("Bytes CRC in hex => 0x%X, CRC Checker => 0x%X\n",
            into_u32(sample_crc),
            crc(sample_crc_payload, BYTE_BOUNDARY + read_data_length)
          );

    return 0;
}

