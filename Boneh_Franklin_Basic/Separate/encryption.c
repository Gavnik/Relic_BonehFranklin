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

// ... [global variables, constants, H1, hash_g2, setup, extract_private_key, encrypt functions]

g1_t P;
g2_t G2, K_pub;
bn_t q, s;

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
    printf("\nEDW?\n");
    md_map(hash, buffer, len);
    //md_map(hash, buffer, size);
}

void print_bn(bn_t num) {
    int length = bn_size_str(num, 10);
    char str[length];
    bn_write_str(str, length, num, 10);
    printf("%s\n", str);
}

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

void encrypt(g2_t c1, uint8_t *c2, char *ID, g2_t K_pub, uint8_t *m, int m_length) {

    // Memory profiling variables
    struct rusage r_usage_start, r_usage_end;
    long memory_usage_start, memory_usage_end;
    
    // Start memory profiling
    getrusage(RUSAGE_SELF, &r_usage_start);
    memory_usage_start = r_usage_start.ru_maxrss ;
    printf("Memory usage-encrypt start: %ld KB\n", memory_usage_start);
    //

    bn_t r, q;
    g1_t Q_ID;
    gt_t g_ID;
    uint8_t hash_of_gIDr[HASH_OUTPUT_SIZE];
    //uint8_t hash_of_gIDr[m_length];

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
        c2[i] = m[i] ^ hash_of_gIDr[i%HASH_OUTPUT_SIZE];
    }

    // End memory profiling
    getrusage(RUSAGE_SELF, &r_usage_end);
    memory_usage_end = r_usage_end.ru_maxrss;
    printf("Memory usage-encrypt end: %ld KB\n", memory_usage_end);

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


    //printf("\nHEYyyyyYYYY\n");
    pc_param_print();
    printf("\n");
    ep_param_print();
  
    // Setup
    setup();

    // Message and ID
    uint8_t message[] = "Your message here";
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA"; //(issue corrected!) up to 32 Bytes? Why in some numbers above 32 it is working?? (problems:40,37,36,35,34,33)

    uint8_t ID[] = "user@domain.com"; //This must be the same in both encyrption and decryption codes!!!!!
    g2_t c1;
    uint8_t encrypted[sizeof(message)];


    // Measure time and memory for decryption
    clock_t start_encryption = clock();
    //size_t memory_before_decryption = malloc_usable_size(NULL);




    encrypt(c1, encrypted, ID, K_pub, message, strlen((char *)message));


    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_encryption = clock();

    printf("\nC1 is:\n");
    g2_print(c1);
    printf("\n");

    //secret s is printed in order for decryption program to create private key (d_ID)
    printf("Secret s: ");
    print_bn(s);

    // Output encrypted data

    printf("Encrypted data: ");
    for (int i = 0; i < sizeof(encrypted); i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\n");


    // Serialize 'c1'
    int c1_size = g2_size_bin(c1,0);
    printf("\nc1_size is: %d\n",c1_size);
    printf("\nRLC_FP_BYTES: %d\n", RLC_FP_BYTES);

    uint8_t c1_serialized[c1_size];
    g2_write_bin(c1_serialized, c1_size, c1, 0);

    // Output serialized 'c1'
    printf("Serialized c1: ");
    for (int i = 0; i < c1_size; i++) {
        printf("%02X", c1_serialized[i]);
    }
    printf("\n");


    printf("Encryption Time: %f seconds\n", ((double) (end_encryption - start_encryption)) / CLOCKS_PER_SEC);


    core_clean();
    return 0;
}
