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

// Converts a byte array to a unsigned 32 bit int in (BE)
#define bytes_to_uint32_t(bytes) ((uint32_t)bytes[0] << 24) + ((uint32_t)bytes[1] << 16)  \
    + ((uint32_t)bytes[2] << 8) + (uint32_t)bytes[3]


uint32_t *read_n_bytes(FILE *file, uint32_t *bytes, size_t n, uint32_t offset) {
    uint32_t l = 0;
    fseek(file, offset, SEEK_SET);
    char buffer;
    while((buffer = fgetc(file)) != EOF && l < n) {
        printf("Bytes in order: byte= %u \n", (uint8_t)buffer);
        bytes[l++] = (uint8_t)buffer;
    }
    return bytes;
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

// A Chunk from the file
typedef struct Chunk {
    // TODO: read type info,  data, crc into seperate fields
    uint32_t length[BYTE_BOUNDARY];
    uint32_t type[BYTE_BOUNDARY];
    uint32_t* data;
    uint32_t crc[BYTE_BOUNDARY];
} Chunk;

uint32_t *read_length(FILE* file, uint32_t *offset) {
    uint32_t length[BYTE_BOUNDARY] = {0};
    puts("Parsing length");
    uint32_t *l = read_n_bytes(file, length, BYTE_BOUNDARY, *offset);
    *offset += BYTE_BOUNDARY;
    return l;

}

uint32_t *read_type(FILE* file, uint32_t *offset) {
    uint32_t type[BYTE_BOUNDARY] = {0};
    puts("Parsing type");
    uint32_t *l = read_n_bytes(file, type, BYTE_BOUNDARY, *offset);
    *offset += BYTE_BOUNDARY;
    return l;
}

uint32_t *read_data(FILE* file, uint32_t *offset, uint32_t length) {
    uint32_t *data = calloc(length, sizeof(uint32_t));
    printf("Parsing data: length=%u\n", length);
    uint32_t *l = read_n_bytes(file, data, length, *offset);
    *offset += length;
    return l;

}

uint32_t *read_crc(FILE* file, uint32_t *offset) {
    uint32_t crc[BYTE_BOUNDARY] = {0};
    puts("Parsing crc");
    uint32_t *l = read_n_bytes(file, crc, BYTE_BOUNDARY, *offset);
    *offset += BYTE_BOUNDARY;
    return l;
}


// read all chunks
void read_chunks(FILE *file) {
    uint32_t offset = PNG_SIGNATURE_LENGTH;
    char buffer;
    while((buffer = fgetc(file) != EOF)) {
        uint32_t *length = read_length(file, &offset);
        for(uint32_t i = 0 ; i < 4; i++) printf("length at %d %d: \n", i, (uint32_t)length[i]);
        if(length) {
            uint32_t *type = read_type(file, &offset);
            if(type) {
                uint32_t *data = read_data(file, &offset, 13/*bytes_to_uint32_t(length)*/);
                if(data) {
                    uint32_t *crc = read_crc(file, &offset);
                }
            }
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

            // TODO: read chunk data, length of chunk data
            read_chunks(file); //,png_file_path);
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

