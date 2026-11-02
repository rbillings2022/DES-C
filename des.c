#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

// DEFINE
#define IP_PERM_SIZE 64
#define EXP_PERM_SIZE 48
#define EFFECTIVE_KEY_SIZE 56
#define FEISTEL_SPLIT_SIZE 32
#define KEY_GEN_SPLIT_SIZE 28

#define BLOCK_BYTES 8
#define HALF_BLOCK_BYTES 4
#define ROUND_COUNT 16
#define ROUND_KEY_BYTES 6
#define SBOX_COUNT 8
#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

//TABLES
static const uint8_t IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
static const uint8_t inverse_IP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};
static const uint8_t expansion[48] = {
    32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};
static const uint8_t p_permutation[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};
static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};
static const uint8_t PC2[48] = {
    14, 17, 11, 24, 1, 5,
     3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
static const uint8_t shifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

// S-boxes: each one is 4 rows x 16 columns stored flat (index = row * 16 + column).
// 6 bits go in, 4 bits come out.
static const uint8_t sbox[SBOX_COUNT][64] = {
    { // S1
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    },
    { // S2
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    },
    { // S3
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    },
    { // S4
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    },
    { // S5
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    },
    { // S6
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    },
    { // S7
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    },
    { // S8
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
};

// PROTOTYPES
size_t stringsize(const char* message);
void permutation_function(const uint8_t *source, uint8_t* new_array, size_t num_bits, const uint8_t* permutation_table);
const char* write_hex_to_file(const uint8_t* block);
const char* write_string_to_file(const uint8_t* block, size_t count);
const char* write_binary_to_file(const uint8_t* block);
void CLEAR(void);
int gen_64_bit_key(uint8_t *buf, size_t len);
static uint32_t rotate_bit_left(uint32_t split, unsigned rotation_sch);
void key_schedule(const uint8_t key[8], uint8_t round_keys[16][6]);

static unsigned int get_bit(const uint8_t *data, unsigned int bit_position);
static void xor_bytes(uint8_t *target, const uint8_t *other, size_t byte_count);
static uint8_t sbox_substitute(unsigned int sbox_index, uint8_t six_bit_input);
void feistel_function(const uint8_t right_half[HALF_BLOCK_BYTES], const uint8_t round_key[ROUND_KEY_BYTES], uint8_t output[HALF_BLOCK_BYTES]);
void des_crypt_block(const uint8_t input_block[BLOCK_BYTES], uint8_t output_block[BLOCK_BYTES], uint8_t round_keys[ROUND_COUNT][ROUND_KEY_BYTES], int mode);

// Interface the whole DES system
int main(){
    const char *message = "Use const when a function or piece of code";
    size_t length = stringsize(message);

    CLEAR();
    uint8_t key[8];
    if (gen_64_bit_key(key, sizeof key) != 0) {
        return 1;
    }

    printf("Key (hex): ");
    for(int byte_index = 0; byte_index < 8; byte_index++){
        printf("%02X ", key[byte_index]);
    }
    printf("\n\n");

    // Derive the 16 round keys once. Encryption and decryption both read this same array.
    uint8_t round_keys[ROUND_COUNT][ROUND_KEY_BYTES] = {0};
    key_schedule(key, round_keys);

    // Process each block.
    for(size_t offset = 0; offset < length ; offset+=8){
        // BLOCKING BYTES OR MODE PHASE

        // Each element in the array are 8 bits. There are 8 elements so the size of the array is 8x8 = 64 bits
        uint8_t des_block[8] ={0}; // Initialize every byte to 0
        size_t remaining = length - offset;
        size_t count = 0;

        if(remaining < 8){
            count = remaining;
        }else{
            count = 8;
        }

        // Create a 8 byte block starting from position offset and number of entries based on count
        memcpy(des_block, message + offset, count);

        // ENCRYPT: plaintext block -> ciphertext block
        uint8_t ciphertext_block[8] = {0};
        des_crypt_block(des_block, ciphertext_block, round_keys, MODE_ENCRYPT);

        // DECRYPT: ciphertext block -> plaintext block (same function, round keys used in reverse)
        uint8_t decrypted_block[8] = {0};
        des_crypt_block(ciphertext_block, decrypted_block, round_keys, MODE_DECRYPT);

        // PRINT RESULTS
        printf("Ciphertext (hex): ");
        for(int byte_index = 0; byte_index < 8; byte_index++){
            printf("%02X ", ciphertext_block[byte_index]);
        }
        printf("\nDecrypted text:   ");
        for(size_t byte_index = 0; byte_index < count; byte_index++){
            printf("%c", decrypted_block[byte_index]);
        }
        printf("\n\n");

        // Ciphertext goes to hex_output.txt, decrypted text goes to string_output.txt
        const char* hex_response = write_hex_to_file(ciphertext_block);
        const char* string_response = write_string_to_file(decrypted_block, count);
        (void)hex_response;
        (void)string_response;
    }

    printf("Ciphertext written to hex_output.txt\n");
    printf("Decrypted text written to string_output.txt\n");

    return 0;
}

void CLEAR(void){
    // Clear Textfile
    FILE *hex_file = fopen("hex_output.txt", "w");
    FILE *string_file = fopen("string_output.txt", "w");
    FILE *binary_file = fopen("binary.txt", "w");

    if(hex_file) fclose(hex_file);
    if(string_file) fclose(string_file);
    if(binary_file) fclose(binary_file);
}
// Functions
size_t stringsize(const char *message){

    size_t length = 0;

    while(message[length] != 0){
        length++;
    }

    return length;
}

void permutation_function(const uint8_t *source, uint8_t* new_array, size_t num_bits, const uint8_t* permutation_table){

    for(unsigned int table_pos = 0; table_pos < num_bits; table_pos++){
        // When we loop through the position numbers -> use it as an index to find the byte/element 
            // Find the bit inside the byte, then find how much it need to shift that bit to be in a least sign
            // bit position 
        unsigned int table_element = permutation_table[table_pos] - 1;
        unsigned int find_src_byte = table_element / 8;
        unsigned int find_src_position = table_element % 8;
        unsigned int bit_shifter = 7 - find_src_position;
        
        // Shift the byte string then & it against 1
        // Example: 01000000 -> 00000001 & 00000001 = 1
        unsigned int bit = (source[find_src_byte] >> bit_shifter) & 1u;

        // Find the element we will start to enter bits
        // Find shifting position to move the bit
        unsigned int find_dest_byte = table_pos / 8;
        unsigned int find_dest_bit_position = table_pos % 8;
        bit_shifter = 7 - find_dest_bit_position;

        new_array[find_dest_byte] |= (unsigned int)(bit << bit_shifter);
    }
}

// Generate Random numbers
int gen_64_bit_key(uint8_t *buf, size_t len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 ? 0 : -1;
}


// Write HEX results to file
const char* write_hex_to_file(const uint8_t* block){
    FILE* f = fopen("hex_output.txt", "a");
    if(f == NULL){
        perror("fopen");
        return "Error, could not open hex_output.txt.";
    }

    for(int i = 0; i <= 7; i++){
        fprintf(f, "%02X ", block[i]);
    }
    fprintf(f, "\n");

    fclose(f);

    return "Data has successfully been written to hex_output.txt.";
}

const char* write_binary_to_file(const uint8_t* block){
    FILE *f = fopen("binary.txt", "a");
    if(f == NULL){
        perror("fopen");
        return "Error, could not open binary.txt.";
    }
    // Print bit string
    for(int j = 0; j < 8; j++){
        for(int i = 7; i >= 0; i--){
            int bit = (block[j] >> i) & 1;
            fprintf(f, "%d", bit);
        }
        fprintf(f, " ");
    }
    fprintf(f, "\n");

    fclose(f);

    return "Data has been written to binary.txt.";
}

const char* write_string_to_file(const uint8_t* block, size_t count){
    FILE *f = fopen("string_output.txt", "a");
    if(f == NULL){
        perror("fopen");
        return "Error, could not open string_output.txt.";
    }
    for(size_t i = 0; i < count; i++){
        fprintf(f, "%c", block[i]);
    }
    fclose(f);

    return "Data has been written to string_output.txt.";
}

static uint32_t rotate_bit_left(uint32_t split, unsigned rotation_sch){
    return ((split << rotation_sch) | (split >> (28 - rotation_sch))) & 0x0FFFFFFF;
}

void key_schedule(const uint8_t key[8], uint8_t round_keys[16][6]){
    uint8_t effective_key[7] = {0};
    permutation_function(key, effective_key, EFFECTIVE_KEY_SIZE, PC1);

    // pack 7 bytes into one 56-bit integer
    // after the loop it stores a hex integer 
    // ex: k = 0x00 B0 B1 B2 B3 B4 B5 B6 (top byte unused, B0 = first key byte).
    uint64_t hex_key_56_bits = 0;
    for(int i = 0; i < 7; i++){
        hex_key_56_bits = (hex_key_56_bits << 8) | effective_key[i];
    }

    uint32_t C = (uint32_t)(hex_key_56_bits >> 28) & 0x0FFFFFFF;
    uint32_t D = (uint32_t)hex_key_56_bits & 0x0FFFFFFF;

    for(int r = 0; r < 16; r++){
        C = rotate_bit_left(C, shifts[r]);
        D = rotate_bit_left(D, shifts[r]);

        uint64_t cd = ((uint64_t)C << 28) | D;
        uint8_t cd_bytes[7];
        for(int i = 0; i < 7; i++)
            cd_bytes[i] = (uint8_t)(cd >> (48 - 8 * i));

        memset(round_keys[r], 0, 6);   // permutation ORs bits in, so zero first
        permutation_function(cd_bytes, round_keys[r], EXP_PERM_SIZE, PC2);
    }
}

// ---------------------------------------------------------------------------
// FEISTEL ROUND PIECES
// ---------------------------------------------------------------------------

// Read one bit from a byte array. bit_position 0 is the leftmost bit of data[0].
static unsigned int get_bit(const uint8_t *data, unsigned int bit_position){
    unsigned int byte_index = bit_position / 8;
    unsigned int bit_in_byte = bit_position % 8;
    return (data[byte_index] >> (7 - bit_in_byte)) & 1u;
}

// target[i] ^= other[i] for every byte
static void xor_bytes(uint8_t *target, const uint8_t *other, size_t byte_count){
    for(size_t byte_index = 0; byte_index < byte_count; byte_index++){
        target[byte_index] ^= other[byte_index];
    }
}

// One S-box lookup: 6 bits in -> 4 bits out.
// The outer two bits (first and last) pick the row, the middle four bits pick the column.
static uint8_t sbox_substitute(unsigned int sbox_index, uint8_t six_bit_input){
    unsigned int outer_bits = ((six_bit_input & 0x20) >> 4) | (six_bit_input & 0x01);
    unsigned int middle_bits = (six_bit_input >> 1) & 0x0F;
    return sbox[sbox_index][outer_bits * 16 + middle_bits];
}

// The DES "f" function, used once per round:
//   32-bit right half -> expand to 48 -> XOR round key -> 8 S-boxes (48 -> 32) -> P permutation
void feistel_function(const uint8_t right_half[HALF_BLOCK_BYTES], const uint8_t round_key[ROUND_KEY_BYTES], uint8_t output[HALF_BLOCK_BYTES]){
    // Expansion function: 32 bits -> 48 bits
    uint8_t expanded_half[ROUND_KEY_BYTES] = {0};
    permutation_function(right_half, expanded_half, EXP_PERM_SIZE, expansion);

    // XOR sub-key and expanded right
    xor_bytes(expanded_half, round_key, ROUND_KEY_BYTES);

    // 3. Substitution: split 48 bits into eight 6-bit groups, each becomes 4 bits
    uint8_t substituted_half[HALF_BLOCK_BYTES] = {0};
    for(unsigned int sbox_index = 0; sbox_index < SBOX_COUNT; sbox_index++){
        uint8_t six_bit_input = 0;
        for(unsigned int bit_offset = 0; bit_offset < 6; bit_offset++){
            six_bit_input = (uint8_t)((six_bit_input << 1) | get_bit(expanded_half, sbox_index * 6 + bit_offset));
        }

        uint8_t four_bit_output = sbox_substitute(sbox_index, six_bit_input);

        // Two S-box outputs fill one byte: even index -> high nibble, odd index -> low nibble
        if(sbox_index % 2 == 0){
            substituted_half[sbox_index / 2] |= (uint8_t)(four_bit_output << 4);
        }else{
            substituted_half[sbox_index / 2] |= four_bit_output;
        }
    }

    // 4. P permutation: shuffle the 32 bits. Zero the output first since the permutation ORs bits in.
    memset(output, 0, HALF_BLOCK_BYTES);
    permutation_function(substituted_half, output, FEISTEL_SPLIT_SIZE, p_permutation);
}

// Encrypt or decrypt every 64-bit block of data.
void des_crypt_block(const uint8_t input_block[BLOCK_BYTES], uint8_t output_block[BLOCK_BYTES], uint8_t round_keys[ROUND_COUNT][ROUND_KEY_BYTES], int mode){
    // Initial permutation
    uint8_t permuted_block[BLOCK_BYTES] = {0};
    permutation_function(input_block, permuted_block, IP_PERM_SIZE, IP);

    // Split into left and right halves (taken from the IP output, not the original input)
    uint8_t left_half[HALF_BLOCK_BYTES];
    uint8_t right_half[HALF_BLOCK_BYTES];
    memcpy(left_half, permuted_block, HALF_BLOCK_BYTES);
    memcpy(right_half, permuted_block + HALF_BLOCK_BYTES, HALF_BLOCK_BYTES);

    // Loop through all 16 Feistel rounds
    for(int round_index = 0; round_index < ROUND_COUNT; round_index++){
        int key_index = (mode == MODE_ENCRYPT) ? round_index : (ROUND_COUNT - 1 - round_index);

        uint8_t feistel_output[HALF_BLOCK_BYTES];
        feistel_function(right_half, round_keys[key_index], feistel_output);

        // new_right = left XOR f(right, key); new_left = old right
        uint8_t new_right_half[HALF_BLOCK_BYTES];
        memcpy(new_right_half, left_half, HALF_BLOCK_BYTES);
        xor_bytes(new_right_half, feistel_output, HALF_BLOCK_BYTES);

        memcpy(left_half, right_half, HALF_BLOCK_BYTES);
        memcpy(right_half, new_right_half, HALF_BLOCK_BYTES);
    }

    // Final swap: the pre-output block is right half followed by left half
    uint8_t pre_output_block[BLOCK_BYTES];
    memcpy(pre_output_block, right_half, HALF_BLOCK_BYTES);
    memcpy(pre_output_block + HALF_BLOCK_BYTES, left_half, HALF_BLOCK_BYTES);

    // Inverse initial permutation
    memset(output_block, 0, BLOCK_BYTES);
    permutation_function(pre_output_block, output_block, IP_PERM_SIZE, inverse_IP);
}