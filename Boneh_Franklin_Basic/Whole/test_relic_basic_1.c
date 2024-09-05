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

//K_pub, c1 -> G2
//Q_ID (receiver's public Key), private_key(receiver) ->G1

g1_t P;
g2_t G2, K_pub;
bn_t q, s;

void H1(g1_t out, uint8_t *in, int len) {
    //uint8_t hash[HASH_OUTPUT_SIZE];
    //md_map(hash, in, len); //it takes strlen() in
    //g1_map(out, hash, HASH_OUTPUT_SIZE);
    g1_map(out, in, len);
}

//void hash_g2(uint8_t *hash, gt_t in) {
void hash_g2(uint8_t *hash, gt_t in, int len) {
    int size = gt_size_bin(in, 0);
    //printf("\nSize is : %d and len is : %d\n",size,len);
    //printf("\na is: %d \n", a);


    uint8_t *buffer = (uint8_t *)malloc(len);    
    if (buffer == NULL) {
    // Handle memory allocation failure
    printf("Memory allocation failed.\n");
    free(buffer);
    return;
    }


    //uint8_t buffer[size];
    gt_write_bin(buffer, size, in, 0);
    md_map(hash, buffer, len);
    //md_map(hash, buffer, size);

    free(buffer);
}

/*
void hash_g2(uint8_t *hash, gt_t in, int len) {

    int size = gt_size_bin(in, 0);
    //printf("\nSize is : %d and len is : %d\n",size,len);
    uint8_t buffer[size];
    gt_write_bin(buffer, size, in, 0);
    md_map(hash, buffer, len);
    //md_map(hash, buffer, size);
}
*/

void setup() {
    // Initialize
    g1_new(P);
    g2_new(K_pub);
    g2_new(G2);
    bn_new(q);
    bn_new(s);

    // Setup the pairing-friendly curve
    //ep_param_set_any();

    // Get the group generators
    g1_get_gen(P);
    printf("\nG1 is:\n");
    g1_print(P);
    g2_get_gen(G2);
    printf("\nG2 is:\n");
    g2_print(G2);

    // Get the order of the group
    g1_get_ord(q);

    // Generate a random master secret
    bn_rand_mod(s, q);

    // Compute the public key
    g2_mul(K_pub, G2, s);
}

void extract_private_key(g1_t private_key, uint8_t *ID, int ID_length, bn_t s) {
    g1_t Q_ID;
    g1_new(Q_ID);
    H1(Q_ID, ID, ID_length);
    g1_mul(private_key, Q_ID, s);
    g1_free(Q_ID);
}

void encrypt(g2_t c1, uint8_t *c2, char *ID, g2_t K_pub, uint8_t *m, int m_length) {

    // Memory profiling variables
    // struct rusage r_usage_start, r_usage_end;
    // long memory_usage_start, memory_usage_end;
    
    // // Start memory profiling
    // getrusage(RUSAGE_SELF, &r_usage_start);
    // memory_usage_start = r_usage_start.ru_maxrss ;
    // printf("Memory usage-encrypt start: %ld KB\n", memory_usage_start);
    //

    bn_t r, q;
    g1_t Q_ID;
    gt_t g_ID;
    uint8_t hash_of_gIDr[HASH_OUTPUT_SIZE];
    //uint8_t hash_of_gIDr[m_length];
    //uint8_t *hash_of_gIDr;

    // Initialize variables
    bn_new(r);
    bn_new(q);
    g1_new(Q_ID);
    gt_new(g_ID);

    // 1. Q_ID = H1(ID)
    // 
    H1(Q_ID, ID, strlen(ID)); // 
    // 2. Choose a random r in Z_q*
    g1_get_ord(q);
    bn_rand_mod(r, q);

    // 3. Compute g_ID = e(Q_ID, K_pub) in G_T
    pc_map(g_ID, Q_ID, K_pub);

    // 4. Compute hash_of_gIDr = H2(g_ID^r)
    gt_exp(g_ID, g_ID, r);
    // a hash function `hash_g2` for G_2 -> {0,1}^n
    //hash_g2(hash_of_gIDr, g_ID, strlen(c2)); //hash2 G2 -> {0,1}^n  , n=strlen(c2) 
    hash_g2(hash_of_gIDr, g_ID, m_length); //hash2 G2 -> {0,1}^n  , n=strlen(m) 

    // 5. Set c = (rP, m XOR H2(g_ID^r))
    g2_mul_gen(c1, r);
    printf("\nMegethos hash_of_gIDr: %d \n", sizeof(hash_of_gIDr));

    
    for (int i = 0; i < m_length; i++) {
        c2[i] = m[i] ^ hash_of_gIDr[i % HASH_OUTPUT_SIZE];
    }


    // End memory profiling
    // getrusage(RUSAGE_SELF, &r_usage_end);
    // memory_usage_end = r_usage_end.ru_maxrss ;
    // printf("Memory usage-encrypt end: %ld KB\n", memory_usage_end);

/*****to memory_usage_start tha einai idio me to memory_usage_end****/

    //
    // Calculate memory usage
    //long memory_used = (memory_usage_end*1024) - (memory_usage_start*1024);
    //printf("Memory used in encrypt: %ld KB\n", memory_used / 1024);
    //

    // Cleanup
    bn_free(r);
    bn_free(q);
    g1_free(Q_ID);
    gt_free(g_ID);
}


void decrypt(uint8_t *m, g2_t c1, uint8_t *v, g1_t d_ID, int m_length) {

    // // Memory profiling variables
    // struct rusage r_usage_start, r_usage_end;
    // long memory_usage_start, memory_usage_end;
    
    // //Start memory profiling
    // getrusage(RUSAGE_CHILDREN, &r_usage_start);
    // memory_usage_start = r_usage_start.ru_maxrss ;
    // printf("Memory usage-decrypt start: %ld KB\n", memory_usage_start);
    // //

    gt_t pairing_result;
    uint8_t hash_of_pairing[HASH_OUTPUT_SIZE];
    //uint8_t hash_of_pairing[m_length];

    gt_new(pairing_result);
    pc_map(pairing_result, d_ID, c1);

    //hash_g2(hash_of_pairing, pairing_result, strlen(v));
    printf("\nstrlen(v) is: %d \n", sizeof(v));
    //printf("\nstrlen(v) is: %d \n", strlen(v));
    printf("\nm_length is: %d \n", m_length);

    hash_g2(hash_of_pairing, pairing_result, m_length);


    for (int i = 0; i < m_length; i++) {
        m[i] = v[i] ^ hash_of_pairing[i % HASH_OUTPUT_SIZE];
    }


    // End memory profiling
    // getrusage(RUSAGE_SELF, &r_usage_end);
    // memory_usage_end = r_usage_end.ru_maxrss ;
    // printf("Memory usage-decrypt end: %ld KB\n", memory_usage_end);

/*****to memory_usage_start tha einai idio me to memory_usage_end****/
    //
    // Calculate memory usage
    //long memory_used = (memory_usage_end*1024) - (memory_usage_start*1024);
    //printf("Memory used in decrypt: %ld KB\n", memory_used / 1024);
    //

    gt_free(pairing_result);
}

int main(void) {
    // Initialize RELIC
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

    
    // Setup
    setup();

    // Message and ID
    
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA  MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA"; //(issue corrected!) up to 32 Bytes? Why in some numbers above 32 it is working?? (problems:40,37,36,35,34,33)
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA  MomomomomoSKOUPAARIBAARI  -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba--hahagsagjhjhfgdkajkjhfbsba--hahagsagjhjhf1";  

    uint8_t message[] = "YOLO";
    //printf("\n%s: \n",message);
    g2_t c1;
    uint8_t encrypted[sizeof(message)];
    
    printf("Size of encrypted message is:\n%d\n",sizeof(message));

    //bn_t r;
    g2_new(c1);
    //bn_new(r);
    uint8_t ID[] = "user@domain.com";

    g1_t d_ID;
    g1_new(d_ID);
    extract_private_key(d_ID, ID, strlen(ID), s);

    // Measure time and memory for encryption
    clock_t start_encryption = clock();
    //size_t memory_before_encryption = malloc_usable_size(NULL);
   
    // Encrypt
    encrypt(c1, encrypted, ID, K_pub, message, strlen((char *)message));
    //encrypt(c1, encrypted, ID, K_pub, message, sizeof(message));
/*
    printf("\nEncrypted is: \n" );
    for (int i=0 ;i<sizeof(message) ;i++ ){
        printf("%c", encrypted[i]);
    }
    printf("\n");
*/
    //size_t memory_after_encryption = malloc_usable_size(NULL);
    clock_t end_encryption = clock();


    //size_t memory_before_decryption = malloc_usable_size(NULL);

    // Decrypt
    uint8_t decrypted[sizeof(message)];
    printf("\nsizeof(message) is: %d\n",sizeof(message));

    //decrypt(decrypted, c1, encrypted, d_ID, sizeof(message));


    // Measure time and memory for decryption
    clock_t start_decryption = clock();
    


    decrypt(decrypted, c1, encrypted, d_ID, strlen((char *)message));


    


    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_decryption = clock();

    // Print results
    printf("Original Message: %s\n", message);
    printf("Decrypted Message: %s\n", decrypted);

    // Print timing results
    printf("Encryption Time: %f seconds\n", ((double) (end_encryption - start_encryption)) / CLOCKS_PER_SEC);
    printf("Decryption Time: %f seconds\n", ((double) (end_decryption - start_decryption)) / CLOCKS_PER_SEC);

    // Print memory usage results
    //printf("Memory Usage (Encryption): %lu bytes\n", memory_after_encryption - memory_before_encryption);
    //printf("Memory Usage (Decryption): %lu bytes\n", memory_after_decryption - memory_before_decryption);


    // Cleanup
    g2_free(c1);
    //bn_free(r);
    g1_free(d_ID);
    g1_free(P);
    g2_free(K_pub);
    g2_free(G2);
    bn_free(q);
    bn_free(s);
    core_clean();
    return 0;
}
