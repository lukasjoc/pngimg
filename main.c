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

#define TODO(message) assert(0 && message)

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
        printf("%u,", (uint8_t)byte);
        bytes[l++] = (uint8_t)byte;
    }
    printf("\n-----\n");

    // next offset
    return offset + n;
}

// read N bytes from offset from n into m
uint8_t read_at_offset(uint8_t *n, uint8_t n_size,
                       uint8_t *m, uint8_t m_size, uint8_t offset) {
    // for(uint8_t i = 0; i < 13; ++i) printf("data chnk %u \n", n[i]);
    uint8_t c = offset;
    uint8_t l = 0;
    assert(m_size < n_size);
    uint8_t o = offset + m_size;
    while(c < o && c < n_size) {
        // printf("l: %u, c: %u, n[c]=%u \n", l,c, n[c]);
        m[l++] = n[++c];
    }
    return o;
}

// Converts a byte array an unsigned 32 bit int
#define into_u32(bytes) (uint32_t)((bytes[0] << 24) + (bytes[1] << 16) \
        + (bytes[2] << 8) + bytes[3])

#define PNG_SIGNATURE_LENGTH 8
#define BYTE_BOUNDARY 4

// Holds some meta information about the PNG that is
// being decoded.
typedef struct PngFile {
    // Count of chunks
    uint32_t chunk_count;

    // path of file
    const char *path;

    // the open file
    FILE *file;
} PngFile;

// A pre-defined byte-array that defines the signature
const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_LENGTH] = {
    137, 80, 78, 71, 13, 10, 26, 10
};

// A single chunk of any type
typedef struct Chunk {
    // the chunk data
    uint8_t *data;

    // the number of bytes for the data
    uint8_t length[BYTE_BOUNDARY];

    // the type name of the chunk
    uint8_t type[BYTE_BOUNDARY];
    uint32_t type_int;

    // the redundancy check
    uint8_t crc[BYTE_BOUNDARY];
} Chunk;

// ------------- Criticial Chunks --------------------------------------------------------
// IHDR (Image Header)
const uint32_t CHUNK_IHDR = 0x49484452;
typedef struct Chunk_Image_Header {
    uint8_t width[BYTE_BOUNDARY];
    uint8_t height[BYTE_BOUNDARY];
    uint8_t bit_depth;
    uint8_t colour_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;
} Chunk_Image_Header;


// TODO: create a bigger struct that combines all the critical chumk structs
// and is returned from the parsing process

// parse the chunk data for the image header chunk type
Chunk_Image_Header parse_chunk_data(Chunk *chunk) {
    if(chunk->type_int != CHUNK_IHDR) NULL;

    uint8_t offset = 0;
    Chunk_Image_Header ihdr_data = {0};
    offset = read_at_offset(chunk->data, 13, ihdr_data.width, BYTE_BOUNDARY, offset);
    offset = read_at_offset(chunk->data, 13, ihdr_data.height, BYTE_BOUNDARY, offset);
    offset = read_at_offset(chunk->data, 13, &ihdr_data.bit_depth, 1, offset);
    offset = read_at_offset(chunk->data, 13, &ihdr_data.colour_type, 1, offset);
    offset = read_at_offset(chunk->data, 13, &ihdr_data.compression_method, 1, offset);
    offset = read_at_offset(chunk->data, 13, &ihdr_data.filter_method, 1, offset);
    offset = read_at_offset(chunk->data, 13, &ihdr_data.interlace_method, 1, offset);
    return ihdr_data;
}

// PLTE (Color Palette)
const uint32_t CHUNK_PLTE = 0x00000000; /* TODO: find png with a palette, support type */;

// IDAT (Image Data)
const uint32_t CHUNK_IDAT = 0x49444154; // TODO: support type

// IEND (Image Trailer)
const uint32_t CHUNK_IEND = 0x49454E44; // TODO: support type
//----------------------------------------------------------------------------------------


// -------- Ancillary chunks -------------------------------------------------------------
const uint32_t CHUNK_cHRM = 0x6348524D; // TODO: support type
const uint32_t CHUNK_bKGD = 0x624B4744; // TODO: support type
const uint32_t CHUNK_pHYs = 0x70485973; // TODO: support type
const uint32_t CHUNK_sBIT = 0x73424954; // TODO: support type
const uint32_t CHUNK_tEXt = 0x74455874; // TODO: support type
const uint32_t CHUNK_iCCP = 0x69434350; // TODO: support type
// ---------------------------------------------------------------------------------------

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


// the file is a valid PNG File
// TODO: refactor this using memcpy
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

// Parse all chunks from a given PngFile
void read_chunks(PngFile *file, Chunk *chunks, size_t chunk_size) {
    // Create the table of crcs
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
        printf("Type END= %.*s, 0x%X\n", BYTE_BOUNDARY, (char*)chunk.type, into_u32(chunk.type));

        // Try to parse the data
        puts("Data START");
        uint32_t length_into = into_u32(chunk.length);
        chunk.data = (uint8_t*)calloc(length_into, sizeof(uint8_t));
        if(chunk.data==NULL) {
            // TODO: error handling
            exit(EXIT_FAILURE);
        }
        offset = read_n_bytes(file->file, chunk.data, length_into, offset);
        puts("Data END");

        // Parse and check current chunks CRC
        puts("CRC START");
        offset = read_n_bytes(file->file, chunk.crc, BYTE_BOUNDARY, offset);
        chunks[file->chunk_count++] = chunk;
        assert(file->chunk_count < chunk_size
                && "More Chunks possible, but not enough memory provided to save them");

        uint8_t *crc_payload = calloc((length_into + BYTE_BOUNDARY), sizeof(uint8_t));
        memcpy(crc_payload, chunk.type, BYTE_BOUNDARY);
        memcpy((crc_payload + BYTE_BOUNDARY), chunk.data, length_into);
        assert(into_u32(chunk.crc)==crc(crc_payload, BYTE_BOUNDARY + length_into)
                && "Redundancy Check Code (CRC) Failure");

        // just in case free the damn thing again 
        free(crc_payload);
        puts("CRC END= valid=true");

        Chunk_Image_Header ihdr_data = parse_chunk_data(&chunk);
        puts("-----------IHDR_DATA--------------------------------");
        printf("Width in Pixels: %u\n",  into_u32(ihdr_data.width));
        printf("Height in Pixels: %u \n", into_u32(ihdr_data.height));
        puts("----------------------------------------------------");

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
            for(uint8_t i = 0; i < 128; i++) free(chunks[i].data);
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

