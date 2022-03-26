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

#define PNG_SIGNATURE_LENGTH 8
#define BYTE_BOUNDARY 4
#define PNG_LENGTH_MAX 32

// Converts a byte array to a unsigned 32 bit int in
#define bytes_to_uint32_t(bytes) ((uint32_t)bytes[0] << 24) + ((uint32_t)bytes[1] << 16)  \
    + ((uint32_t)bytes[2] << 8) + (uint32_t)bytes[3]

// puts n bytes from file by offset into bytes
void read_n_bytes(FILE *file, uint8_t *bytes, size_t n, uint32_t offset) {
    uint32_t l = 0;
    printf("Reading Bytes offset from=%u to=%lu \n", offset, offset + n);
    fseek(file, offset, SEEK_SET);
    uint8_t byte;
    while(l < n) {
        byte = (uint8_t)fgetc(file);
        if((int8_t)byte == EOF) break;
        printf("Bytes in order: byte= %u, l=%u, n=%zu, \n", byte, l, n);
        bytes[l++] = byte;
    }
}

// the file is a valid PNG File
bool check_png_signature(FILE* file, const char *png_file_path ) {
    const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_LENGTH] = {
        137, 80, 78, 71, 13, 10, 26, 10
    };
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
    uint32_t offset = PNG_SIGNATURE_LENGTH;
    char buffer;

    while((buffer = fgetc(file) != EOF)) {
        // Parse the length
        uint8_t length[BYTE_BOUNDARY] = {0};
        puts("Length START");
        read_n_bytes(file, length, BYTE_BOUNDARY, offset);
        offset += BYTE_BOUNDARY;
        puts("Length END");

        // Parse the type
        puts("Type START");
        uint8_t type[BYTE_BOUNDARY] = {0};
        read_n_bytes(file, type, BYTE_BOUNDARY, offset);
        offset += BYTE_BOUNDARY;
        printf("Type END= %s\n", (char*)type);

        // Try to parse the data
        puts("Data START");
        uint32_t length_into = bytes_to_uint32_t(length);
        printf("Data length uint32_t=%u\n", length_into);
        uint8_t data[PNG_LENGTH_MAX*1024] = {0};
        read_n_bytes(file, data, length_into, offset);
        offset += length_into;
        puts("Data END");

        // Parse the crc
        puts("Crc START");
        uint8_t crc[BYTE_BOUNDARY] = {0};
        read_n_bytes(file, crc, BYTE_BOUNDARY, offset);
        offset += BYTE_BOUNDARY;
        puts("Crc END");
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

            // TODO: read chunk data, length of chunk data
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

