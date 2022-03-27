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
#define into_u32(bytes) (uint32_t)((bytes[0] << 24) + (bytes[1] << 16) \
        + (bytes[2] << 8) + bytes[3])

#define PNG_SIGNATURE_LENGTH 8
#define BYTE_BOUNDARY 4
#define PNG_LENGTH_MAX 32
#define PNG_DATA_CHUNK_SIZE PNG_LENGTH_MAX * 1024

// A pre-defined byte-array that defines the signature
const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_LENGTH] = {
    137, 80, 78, 71, 13, 10, 26, 10
};


// Criticial Chunks

// IHDR (Image Header)
const uint32_t CHUNK_IHDR = 0x49484452;

// PLTE (Color Palette)
const uint32_t CHUNK_PLTE = 0x00000000; /* TODO: find png with a palette */;

// IDAT (Image Data)
const uint32_t CHUNK_IDAT = 0x49444154;

// IEND (Image Trailer)
const uint32_t CHUNK_IEND = 0x49454E44;

// Ancillary chunks
const uint32_t CHUNK_cHRM = 0x6348524D; // TODO: support type
const uint32_t CHUNK_bKGD = 0x624B4744; // TODO: support type
const uint32_t CHUNK_pHYs = 0x70485973; // TODO: support type
const uint32_t CHUNK_sBIT = 0x73424954; // TODO: support type
const uint32_t CHUNK_tEXt = 0x74455874; // TODO: support type
const uint32_t CHUNK_iCCP = 0x69434350; // TODO: support type

typedef struct PngFile {
    // Count of chunks
    uint32_t chunk_count;

    // path of file
    const char *path;

    // the open file
    FILE *file;
} PngFile;

// A single chunk of any type
typedef struct Chunk {
    // TODO: go deeper into the individual chunk data
    // of each chunk
    // the data of the chunk (lazyly as a static array -)
    uint8_t data[PNG_DATA_CHUNK_SIZE];

    // the number of bytes for the data
    uint8_t length[BYTE_BOUNDARY];

    // the type name of the chunk
    uint8_t type[BYTE_BOUNDARY];
    uint32_t type_int;

    // the redundancy check
    uint8_t crc[BYTE_BOUNDARY];
} Chunk;

#define CRC_MAX_SIZE 256
// CRC Handling Code  https://www.w3.org/TR/PNG/#D-CRCAppendix
// Table of CRCs of all 8-bit messages.
static uint32_t crc_table[CRC_MAX_SIZE];

// Flag: has the table been computed? Initially false.
int crc_table_computed = 0;

// Make the table for a fast CRC.
void make_crc_table(void) {
    uint32_t c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = (uint32_t) n;
        for (k = 0; k < 8; k++) {
            if (c & 1) {
                c = 0xedb88320L ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}


// Update a running CRC with the bytes buf[0..len-1]--the CRC
// should be initialized to all 1's, and the transmitted value
// is the 1's complement of the final running CRC (see the
// crc() routine below).
uint32_t update_crc(uint32_t crc, unsigned char *buf, int len) {
    uint32_t c = crc;
    int n;

    if (!crc_table_computed) {
        make_crc_table();
    }
    for (n = 0; n < len; n++) {
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    return c;
}

// Return the CRC of the bytes buf[0..len-1].
uint32_t crc(unsigned char *buf, int len) {
    return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}
//----------------------------------------------------------------------------------------

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
        assert((uint8_t)buffer==current_signature && "PNG Signature not valid");
        signature_length++;
    }
    return true;
}

// read all chunks
void read_chunks(PngFile *file, Chunk *chunks, size_t chunk_size) {
    // Create the table of crcs
    // make_crc_table();

    //for(int i = 0; i < CRC_MAX_SIZE; ++i) {
    //    printf("CRC = 0x%X \n ", crc_table[i]);
    //}

    // #if 0
    off_t offset = PNG_SIGNATURE_LENGTH;
    while(fgetc(file->file) != EOF || file->chunk_count > chunk_size) {
        Chunk chunk = {0};

        // Parse the length
        puts("Length START");
        offset = read_n_bytes(file->file, chunk.length, BYTE_BOUNDARY, offset);
        puts("Length END");

        // Parse the type
        puts("Type START");
        offset = read_n_bytes(file->file, chunk.type, BYTE_BOUNDARY, offset);
        chunk.type_int = into_u32(chunk.type);
        printf("Type END= %.*s, 0x%X\n", 4, (char*)chunk.type, into_u32(chunk.type));

        // Try to parse the data
        puts("Data START");
        uint32_t length_into = into_u32(chunk.length);
        offset = read_n_bytes(file->file, chunk.data, length_into, offset);
        puts("Data END");

        // Parse the CRC
        puts("CRC START");
        offset = read_n_bytes(file->file, chunk.crc, BYTE_BOUNDARY, offset);
        chunks[file->chunk_count++] = chunk;
        assert(file->chunk_count < chunk_size
                && "More Chunks possible, but not enough memory provided to save them");

        // TODO: Check if type + data is the parsed CRC if not then assert false and exit
        // TODO: i dont like this memcpy really the only choice here, loops are equally as
        // bad ;( ?
        // FIXME: CRC parsing seems to be working BUT:
        //  it seems like the reader is reading not enough data
        //  and thats why some crcs, for IDAT/ICCP etc. chunks, with more data
        //  dont work. 
        #if 0
        uint8_t crc_payload[BYTE_BOUNDARY + PNG_DATA_CHUNK_SIZE] = {0};
        memcpy(crc_payload, chunk.type, BYTE_BOUNDARY);
        memcpy(crc_payload+BYTE_BOUNDARY, chunk.data, length_into);
        assert(into_u32(chunk.crc)==crc(crc_payload, BYTE_BOUNDARY + length_into)
                && "Redundancy Check Code (CRC) Failure");
        #endif
        puts("CRC END= valid=true");

        // check if the first chunk is the IHDR chunk
        // if not exit fatally
        if((file->chunk_count == 1) && (chunk.type_int != CHUNK_IHDR)) {
            fprintf(stderr,
                    "ERROR: Invalid Chunk Order. IHDR needs to the first chunk: found = %s\n",
                    chunk.type);
            exit(EXIT_FAILURE);
        }

        // check if the current chunk is the IEND chunk
        // if then exit and finish
        if(chunk.type_int == CHUNK_IEND) {
            puts("IEND chunk reached official PNG data has been parsed");
            printf("Chunks parsed: count=%d \n", file->chunk_count);
            break;
        }
    }
    // #endif
}

void usage(FILE *file, const char* program_name) {
    fprintf(file, "pngimg PNG Decoder\n");
    fprintf(file, "Usage: %s <file.png>\n", program_name);
}

int main(int argc, char **argv) {
    const char* png_file_path = argv[1];

    // no args.. show usage
    if(argc < 2) {
        usage(stderr, argv[0]);
        exit(EXIT_SUCCESS);
    }

    if(argc > 1 && png_file_path) {
        printf("Reading PNG : %s\n", png_file_path);
        FILE *file = fopen(png_file_path, "rb");
        if(file == NULL) {
            // TODO: Check if file exists
            // TODO: Check for file extension
            // TODO: Add better Error handling
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
            PngFile png_file = {
                .file = file,
                .path = png_file_path,
            };

            Chunk chunks[128] = {0};
            read_chunks(&png_file, chunks, 128);

            //for(int i = 0; i < 128; ++i) {
            //    printf("CHUNK: 0x%X\n", chunks[i].type_int);
            //}
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

