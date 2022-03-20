#define _XOPEN_SOURCE 600
#include <stdlib.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

// PNG Image
// IHDR -> ... IEND

// A Chunk from the file
typedef struct Chunk {
    // The Length of the Chunk
    uint64_t data_length;

    // The Chunk Type
    uint64_t type;

    // The Chunk data
    uint64_t data;

    // The CRC of the Chunk 
    uint64_t crc;
}Chunk;

#define PNG_SIGNATURE_LENGTH 8

// the file is a valid PNG File
bool check_png_signature(FILE* file, const char *png_file_path ) {
    const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_LENGTH] = {
        137, 80, 78, 71, 13, 10, 26, 10
    };

    char buffer;
    uint8_t signature_length = 0;
    // uint8_t signature[PNG_SIGNATURE_LENGTH] = {0};
    while((buffer = fgetc(file)) != EOF && signature_length < PNG_SIGNATURE_LENGTH) {
        uint8_t current_signature = PNG_SIGNATURE[signature_length];

        // signature[signature_length] = buffer;
        printf("Parsing Signature: path=%s, signature_length=%u, buffer=%u, png_buffer=%u\n",
                    png_file_path, signature_length, (uint8_t)buffer, current_signature);

        if((uint8_t)buffer!=current_signature) return false;
        signature_length++;
    }
    // TODO: check if the bytes are equal
    return true;
}

int main(int argc, char **argv) {
    const char* program = argv[0];
    const char* png_file_path = argv[1];

    if(argc < 2) {
        fprintf(stderr, "pngimg PNG file parser\n");
        fprintf(stderr, "Usage: %s file\n", program);
    }

    if(argc > 1 && png_file_path) {
        // PNG File Passed
        printf("reading PNG : %s\n", png_file_path);
        FILE *file = fopen(png_file_path , "rb");
        if(file == NULL) {
            // TODO: Check if file exists
            // TODO: Check for file extension
            fprintf(stderr, "ERROR: could not read file: %s\n", png_file_path);
            fclose(file);
            return EXIT_FAILURE;
        }

        // Check that the PNG File Signature exists.
        bool png_signature_valid = check_png_signature(file, png_file_path );

        if(png_signature_valid) {
            // hand the png image stream to the parser, that parses
            // all the chunks
            puts("PNG has a valid signature");
        }else {
            // return to the user and exit
            puts("PNG doesn't have a valid signature");
            fclose(file);
            return EXIT_FAILURE;
        }

        fclose(file);
    }
    return EXIT_SUCCESS;
}

