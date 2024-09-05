//Copyright (c) 2023-2024 The Relic_BonehFranklin project authors
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#include <relic.h>
#include <relic_test.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/resource.h>


#define HASH_OUTPUT_SIZE 32

// ... [global variables, constants, H1, hash_g2, setup, extract_private_key, decrypt functions]
//K_pub, c1 -> G2
//Q_ID (receiver's public Key), private_key(receiver) ->G1

g1_t P;
g2_t G2;
bn_t q;

void H1(g1_t out, uint8_t *in, int len) {
    uint8_t hash[HASH_OUTPUT_SIZE];
    md_map(hash, in, len); //it takes strlen() in
    g1_map(out, hash, HASH_OUTPUT_SIZE);
}

//void hash_g2(uint8_t *hash, gt_t in) {
void hash_g2(uint8_t *hash, gt_t in, int len) {
    int size = gt_size_bin(in, 0);
    //printf("\nSize is : %d and len is : %d\n",size,len);
    uint8_t buffer[size];
    gt_write_bin(buffer, size, in, 0);
    md_map(hash, buffer, len);
    //md_map(hash, buffer, size);
}

void setup() {
    // Initialize
    g1_new(P);
    g2_new(G2);
    bn_new(q);
    

    // Setup the pairing-friendly curve
    //ep_param_set_any();

    // Get the group generators
    g1_get_gen(P);
//    printf("\nG1 is:\n");
//    g1_print(P);
    g2_get_gen(G2);
//    printf("\nG2 is:\n");
//    g2_print(G2);
    // Get the order of the group
    g1_get_ord(q);

}

//reads secret s that is provided from "encryption" program
void read_bn_from_input(bn_t num) {
    char input_str[1024]; // Adjust the size as needed
    scanf("%s", input_str);
    bn_read_str(num, input_str, strlen(input_str), 10);
}

void extract_private_key(g1_t private_key, uint8_t *ID, int ID_length, bn_t s) {
    g1_t Q_ID;
    g1_new(Q_ID);
    H1(Q_ID, ID, ID_length);
    g1_mul(private_key, Q_ID, s);
    g1_free(Q_ID);
}

void decrypt(uint8_t *m, g2_t c1, uint8_t *v, g1_t d_ID, int m_length) {

    // Memory profiling variables
    struct rusage r_usage_start, r_usage_end;
    long memory_usage_start, memory_usage_end;
    
    // Start memory profiling
    getrusage(RUSAGE_SELF, &r_usage_start);
    memory_usage_start = r_usage_start.ru_maxrss / 1024;
//    printf("Memory usage-decrypt start: %ld KB\n", memory_usage_start);
    //

    gt_t pairing_result;
    uint8_t hash_of_pairing[HASH_OUTPUT_SIZE];
    //uint8_t hash_of_pairing[m_length];

    gt_new(pairing_result);
    pc_map(pairing_result, d_ID, c1);

    //hash_g2(hash_of_pairing, pairing_result, strlen(v));
//    printf("\nstrlen(v) is: %d \n", sizeof(v));
    //printf("\nstrlen(v) is: %d \n", strlen(v));
//    printf("\nm_length is: %d \n", m_length);

    hash_g2(hash_of_pairing, pairing_result, m_length);


    for (int i = 0; i < m_length; i++) {
        m[i] = v[i] ^ hash_of_pairing[i%HASH_OUTPUT_SIZE];
    }
    m[m_length]='\0';
    
    // End memory profiling
    getrusage(RUSAGE_SELF, &r_usage_end);
    memory_usage_end = r_usage_end.ru_maxrss / 1024;
//    printf("Memory usage-decrypt end: %ld KB\n", memory_usage_end);

/*****to memory_usage_start tha einai idio me to memory_usage_end****/
    //
    // Calculate memory usage
    //long memory_used = (memory_usage_end*1024) - (memory_usage_start*1024);
    //printf("Memory used in decrypt: %ld KB\n", memory_used / 1024);
    //

    gt_free(pairing_result);
}

// Function to convert hex string to byte array
void hex_string_to_byte_array(const char *hex_str, uint8_t *byte_array, int byte_array_length) {
    for (int i = 0; i < byte_array_length; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}


int main(void) {
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }
    pc_param_set_any();
    


    //ep_param_set(B12_P638); // Barreto-Lynn-Scott sec->160bits 
    //ep_param_set(B12_P377); // Barreto-Lynn-Scott sec->128bits 
    //ep_param_set(B12_P381); // Barreto-Lynn-Scott sec->128bits 

    //ep_param_set(B24_P315); // Kachisa-Scott-Schaefer sec->128bits
    ep_param_set(BN_P382); // Kachisa-Scott-Schaefer sec->128bits 
    //ep_param_set(B12_P383); // Kachisa-Scott-Schaefer sec->128bits
    //ep_param_set(BN_P446); // Kachisa-Scott-Schaefer sec->128bits 
    //ep_param_set(B12_P446); // Kachisa-Scott-Schaefer sec->128bits

    //ep_param_set(K18_P638); // Kachisa-Scott-Schaefer sec->192bits
    //ep_param_set(B24_P509); // Kachisa-Scott-Schaefer sec->192bits

//    ep_param_set(BN_P638); // Barreto-Naehrig sec->160bits 
    //ep_param_set(BN_P254); // Barreto-Naehrig sec->112bits 
    //ep_param_set(BN_P256); // Barreto-Naehrig sec->112bits 
//    ep_param_set(BN_P158); // Barreto-Naehrig sec->78bits 


    pc_param_print();
    printf("\n");
    ep_param_print();
    
    setup();

    char c1_serialized_hex[2001]; // Ensure this size is sufficient
    char encrypted_hex[1024];     // Ensure this size is sufficient
    int m_length;

    // Read secret 's'
    bn_t s;
    bn_new(s);
    printf("Enter secret s: ");
    read_bn_from_input(s);

        // Read serialized 'c1' from console
    printf("Enter serialized c1 in hex format: ");
    scanf("%2000s", c1_serialized_hex);
    int c1_length = strlen(c1_serialized_hex) / 2;
    printf("\nc1_length is : %d\n",c1_length);
    uint8_t c1_serialized[c1_length];
    hex_string_to_byte_array(c1_serialized_hex, c1_serialized, c1_length);

/***********
    // Read serialized 'c1' from console
    printf("Enter serialized c1 in hex format: ");
    scanf("%s", c1_serialized_hex);
    int c1_length = strlen(c1_serialized_hex) / 2;
    uint8_t c1_serialized[c1_length];
    hex_string_to_byte_array(c1_serialized_hex, c1_serialized, c1_length);
*********/
    // Read encrypted data from console
    // Read encrypted data from console
    printf("Enter encrypted data in hex format: ");
    scanf("%1023s", encrypted_hex);
    m_length = strlen(encrypted_hex) / 2;
    uint8_t encrypted[m_length];
    hex_string_to_byte_array(encrypted_hex, encrypted, m_length);
/*******
    printf("Enter encrypted data in hex format: ");
    scanf("%s", encrypted_hex);
    m_length = strlen(encrypted_hex) / 2;
    uint8_t encrypted[m_length];
    hex_string_to_byte_array(encrypted_hex, encrypted, m_length);
*******/
    printf("\nEncrypted data is: ");
    for (int i = 0; i < m_length; i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\n");

    // Deserialize 'c1'
    g2_t c1;

    g2_read_bin(c1, c1_serialized, c1_length); 
    //g2_read_bin(c1, c1_serialized, c1_length);

        // Display 'c1' as hexadecimal
    printf("\nSerialized c1 in hex format is: ");
    for (int i = 0; i < c1_length; i++) {
        printf("%02X", c1_serialized[i]);
    }
    printf("\n");

    printf("C1 in G2 is:\n");
    g2_print(c1);
    printf("\n");
    

    // Extract private key and decrypt
    g1_t d_ID;
    g1_new(d_ID);
    uint8_t ID[] = "user@domain.com"; //This must be the same in both encyrption and decryption codes!!!!!
    extract_private_key(d_ID, ID, strlen((char *)ID), s);
    uint8_t decrypted[m_length];

    printf("\n");

    // Measure time and memory for decryption
    clock_t start_decryption = clock(); // should extract private key be measured in the decryption time?


    decrypt(decrypted, c1, encrypted, d_ID, m_length-1);

    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_decryption = clock();

    // Output the decrypted message
    printf("Decrypted Message: %s\n", decrypted);

    printf("Decryption Time: %f seconds\n", ((double) (end_decryption - start_decryption)) / CLOCKS_PER_SEC);


    // Cleanup
    g1_free(d_ID);
    g2_free(c1);
    bn_free(s);
    core_clean();



    return 0;
}

