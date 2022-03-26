// PNG File Format Decoder
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

// Converts a byte array an unsigned 32 bit int
#define into_u32(bytes) (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]

#define PNG_SIGNATURE_LENGTH 8
#define BYTE_BOUNDARY 4
#define PNG_LENGTH_MAX 32

// A pre-defined byte-array that defines the signature
const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_LENGTH] = {
    137, 80, 78, 71, 13, 10, 26, 10
};

// IHDR (Image Header)
const uint32_t CHUNK_IHDR = 0x49484452;

// IDAT (Image Data)
const uint32_t CHUNK_IDAT = 0x49444154;

// IEND (Image Trailer)
const uint32_t CHUNK_IEND = 0x49454E44;

const uint32_t CHUNK_cHRM = 0x6348524D; // TODO: support type
const uint32_t CHUNK_bKGD = 0x624B4744; // TODO: support type
const uint32_t CHUNK_pHYs = 0x70485973; // TODO: support type
const uint32_t CHUNK_sBIT = 0x73424954; // TODO: support type
const uint32_t CHUNK_tEXt = 0x74455874; // TODO: support type
const uint32_t CHUNK_iCCP = 0x69434350; // TODO: support type

// puts N bytes from file by offset into bytes and returns the next offset
// if it was successfull next offset is n + offset given in
uint32_t read_n_bytes(FILE *file, uint8_t *bytes, size_t n, off_t offset) {
    printf("Reading (%zu bytes ) from offset=%llu, target=%llu \n", n, offset, offset + n);

    int fseek_ok = fseek(file, offset, SEEK_SET);
    if(fseek_ok == -1) {
        fprintf(stderr, "ERROR: could not fseek offset %lld", offset);
    }

    uint32_t l = 0;
    char byte;
    while(l < n) {
        byte = fgetc(file);
        if(byte == EOF) break;
        printf("%u,", (uint8_t)byte);
        bytes[l++] = (uint8_t)byte;
    }
    printf("\n-----\n");

    // next offset
    return offset + n;
}

// the file is a valid PNG File
bool check_png_signature(FILE *file, const char *png_file_path ) {
    char buffer;
    uint8_t signature_length = 0;
    while((buffer = fgetc(file)) != EOF && signature_length < PNG_SIGNATURE_LENGTH) {
        uint8_t current_signature = PNG_SIGNATURE[signature_length];
        printf("Parsing Signature: path=%s, signature_length=%u, buffer=%u, png_buffer=%u\n",
                png_file_path, signature_length, (uint8_t)buffer, current_signature);
        if((uint8_t)buffer!=current_signature) return false;
        signature_length++;
    }
    return true;
}

// read all chunks
void read_chunks(FILE *file) {
    off_t offset = PNG_SIGNATURE_LENGTH;
    while(fgetc(file) != EOF) {
        // Parse the length
        uint8_t length[BYTE_BOUNDARY] = {0};
        puts("Length START");
        offset = read_n_bytes(file, length, BYTE_BOUNDARY, offset);
        puts("Length END");

        // Parse the type
        puts("Type START");
        uint8_t type[BYTE_BOUNDARY] = {0};
        offset = read_n_bytes(file, type, BYTE_BOUNDARY, offset);
        printf("Type END= %s, 0x%X\n", (char*)type, into_u32(type));

        // Try to parse the data
        puts("Data START");
        uint32_t length_into = into_u32(length);
        uint8_t data[PNG_LENGTH_MAX*1024] = {0};
        offset = read_n_bytes(file, data, length_into, offset);
        puts("Data END");

        // Parse the crc
        puts("CRC START");
        uint8_t crc[BYTE_BOUNDARY] = {0};
        offset = read_n_bytes(file, crc, BYTE_BOUNDARY, offset);
        puts("CRC END");

        if(into_u32(type) == CHUNK_IEND) {
            // official png data has been parsed
            printf("parsing done IEND chunk was reached ...\n");
            break;
        }
    }
}

int main(int argc, char **argv) {
    const char* program = argv[0];
    const char* png_file_path = argv[1];

    if(argc < 2) {
        fprintf(stderr, "pngimg PNG file parser\n");
        fprintf(stderr, "Usage: %s file\n", program);
    }

    if(argc > 1 && png_file_path) {
        printf("Reading PNG : %s\n", png_file_path);
        FILE *file = fopen(png_file_path, "rb");
        if(file == NULL) {
            // TODO: Check if file exists
            // TODO: Check for file extension
            fprintf(stderr, "ERROR: could not read file: %s\n", png_file_path);
            fclose(file);
            return EXIT_FAILURE;
        }

        // Check that the PNG File Signature exists.
        puts("Verifying PNG File Signature");
        bool png_signature_valid = check_png_signature(file, png_file_path );
        if(png_signature_valid) {
            // hand the png image stream to the parser, that parses
            // all the chunks
            puts("PNG File Signature valid");
            read_chunks(file);
        } else {
            // return to the user and exit
            puts("PNG doesn't have a valid signature");
            fclose(file);
            return EXIT_FAILURE;
        }

        fclose(file);
    }
    return EXIT_SUCCESS;
}

