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


// Define global variables and parameters
g1_t P1, Ppub; // P1->generator of G1, Ppub->Publuc Key
g2_t  P2, d_ID ; // 
bn_t s, p; //s->Master Secret, p->order of a group (G1 or G2)


//H1


void H1(g2_t out, uint8_t *in, int len) {
    uint8_t hash[HASH_OUTPUT_SIZE];
    md_map(hash, in, len);
    g2_map(out, hash, HASH_OUTPUT_SIZE);
}
//H2   

void H2(uint8_t *hash, gt_t in, int len) {
    int size = gt_size_bin(in, 0);
    uint8_t buffer[size];
    gt_write_bin(buffer, size, in, 0);
    md_map(hash, buffer, len);
    //md_map(hash, buffer, HASH_OUTPUT_SIZE);
}


//H3
//let's have m_length taken from strlen() not from sizeof(). strlen("hi")=2 , sizeof("hi")=3. 
//In concatenated_input we will do [2*m_length]. In memcpy we will do (..,..,m_length+1)

void H3(bn_t result, uint8_t *input1, uint8_t *input2, int m_length) {
    uint8_t hash_output[HASH_OUTPUT_SIZE]; // HASH_OUTPUT_SIZE depends on the hash function used
    uint8_t concatenated_input[2*m_length+1];

    // Step 1: Concatenate input1 and input2
    memcpy(concatenated_input, input1, m_length+1);
    memcpy(concatenated_input + m_length, input2, m_length+1);

    // Step 2: Hash the concatenated string
    md_map(hash_output, concatenated_input, 2*m_length);

    // Step 3: Map the hash to Zp*
    bn_t hash_as_bn;
    bn_new(hash_as_bn);
    bn_read_bin(hash_as_bn, hash_output, HASH_OUTPUT_SIZE);

    // 'p' is the order
    bn_mod(result, hash_as_bn, p);

    bn_free(hash_as_bn);
}

//H4

void H4(uint8_t *output, uint8_t *input, int m_length) {
   // uint8_t hash[HASH_OUTPUT_SIZE]; // HASH_FUNCTION_OUTPUT_SIZE is the output size of the chosen hash function

    // Step 1: Hash the input
    //md_map(hash, input, m_length);
    md_map(output, input, m_length);
    //md_map(output, input, HASH_OUTPUT_SIZE);
}

//Setup

void setup() {
    // Initialize
    g1_new(P1);
    g2_new(P2);
    bn_new(p);

    // Setup the pairing-friendly curve
    //ep_param_set_any();

    // Get the group generators
    g1_get_gen(P1); 
    // printf("\nG1 gen is:\n");
    // g1_print(P1);
    g2_get_gen(P2);
    // printf("\nG2 gen is:\n");
    // g2_print(P2);
    // Get the order of the group
    g1_get_ord(p);

    // Generate a random master secret
    bn_rand_mod(s, p);

    // Compute the public key
    g1_mul(Ppub, P1, s);
}

//Extract Private

void extract_private_key(g2_t d_ID, uint8_t *ID, int ID_length, bn_t s) {
    g2_t Q_ID;

    // Initialize variables
    g2_new(Q_ID);

    // Extract private key d_ID
    H1(Q_ID, ID, ID_length);
    g2_mul(d_ID, Q_ID, s);

    // Cleanup
    g2_free(Q_ID);
}

//reads secret s that is provided from "encryption" program
void read_bn_from_input(bn_t num) {
    char input_str[1024]; // Adjust the size as needed
    scanf("%s", input_str);
    bn_read_str(num, input_str, strlen(input_str), 10);
}

//String to Byte
void hex_string_to_byte_array(const char *hex_str, uint8_t *byte_array, int byte_array_length) {
    for (int i = 0; i < byte_array_length; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}

//Decrypt

int decrypt(uint8_t *M, g1_t C1, uint8_t *C2, uint8_t *C3, g2_t d_ID, int m_length) {
    gt_t C1_ID;
    g1_t newC1;
    bn_t r;
    uint8_t hash_of_C1_ID[HASH_OUTPUT_SIZE];
    uint8_t sigma[m_length]; 
    uint8_t hash_of_sigma[HASH_OUTPUT_SIZE]; //for H4sigma
    // Memory profiling variables
    struct rusage r_usage_start, r_usage_end;
    long memory_usage_start, memory_usage_end;
    
    // Start memory profiling
    getrusage(RUSAGE_SELF, &r_usage_start);
    memory_usage_start = r_usage_start.ru_maxrss / 1024;
    // printf("Memory usage-decrypt start: %ld KB\n", memory_usage_start);
    //

    // Initialize variables
    gt_new(C1_ID);
    bn_new(r);
    g1_new(newC1);

    // Compute e(C1,d_ID)
    pc_map(C1_ID, C1, d_ID);
    // Compute H2(e(C1,d_ID))
    H2(hash_of_C1_ID, C1_ID, m_length);
    //compute σ=C2⊕H2(e(C1,dID))

   // *********** THE FOLLOWING IS IN ORDER TO HAVE CORRECT DECRYPTION FOR MESSAGES BIGGER THATN HASH_OUTPUT_SIZE!!!****
    
    if (m_length<HASH_OUTPUT_SIZE){
        for (int i = 0; i < m_length; i++) {
            sigma[i] = C2[i] ^ hash_of_C1_ID[i];
        }
        //compute H4(sigma)
        H4(hash_of_sigma, sigma, m_length);
        //compute M=C3⊕H4(σ)
        for (int i = 0; i < m_length; i++) {
            M[i] = C3[i] ^ hash_of_sigma[i];
        }
    }else{
        for (int i = 0; i < HASH_OUTPUT_SIZE; i++) {
            sigma[i] = C2[i] ^ hash_of_C1_ID[i];
        }
        for (int i = HASH_OUTPUT_SIZE; i < m_length; i++) {
            sigma[i] = C2[i];
        }
        //compute H4(sigma)
        H4(hash_of_sigma, sigma, m_length);
        //compute M=C3⊕H4(σ)
        for (int i = 0; i < HASH_OUTPUT_SIZE; i++) {
            M[i] = C3[i] ^ hash_of_sigma[i];
        }
        for (int i = HASH_OUTPUT_SIZE; i < m_length; i++) {
            M[i] = C3[i];
        }
    }
//************************************

    M[m_length] = '\0'; //we use strlen() everywhere, so '\0' in strings is not inherrited! We need to add it!!
    //compute r=H3(σ,M)
    H3(r, sigma, M, m_length);
    //check that C1 = rP1
    g1_mul(newC1, P1, r);
   
    // printf("\nnewC1 is:\n");
    // g1_print(newC1);
    // printf("\n");
    // printf("\nDecrypted Message: %s\n", M);

    if (g1_cmp(C1, newC1) != RLC_EQ){
        //printf("\nThe decryption is rejected! :'(\n");
        return 0;
    } else {
        //printf("\nThe decryption is perfect!! :-*\n");
        return 1;
    }
   


    // End memory profiling
    getrusage(RUSAGE_SELF, &r_usage_end);
    memory_usage_end = r_usage_end.ru_maxrss / 1024;
    //printf("Memory usage-decrypt end: %ld KB\n", memory_usage_end);

/*****to memory_usage_start tha einai idio me to memory_usage_end****/
    //
    // Calculate memory usage
    //long memory_used = (memory_usage_end*1024) - (memory_usage_start*1024);
    //printf("Memory used in decrypt: %ld KB\n", memory_used / 1024);
    //

    gt_free(C1_ID);
    bn_free(r);
    g1_free(newC1);
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
    printf("\n");

    // Setup global parameters
    setup();

    char c1_serialized_hex[2001]; // Ensure this size is sufficient
    char c2_hex[1024];     // Ensure this size is sufficient
    char c3_hex[1024];     // Ensure this size is sufficient. Here is the encrypted M

    int m_length;

    // Read secret 's'
    bn_t s;
    bn_new(s);
    printf("Enter secret s: ");
    read_bn_from_input(s);

    printf("\n");


        // Read serialized 'c1' from console
    printf("Enter serialized c1 in hex format: ");
    scanf("%2000s", c1_serialized_hex);
    int c1_length = strlen(c1_serialized_hex) / 2;
    printf("\nc1_length is : %d\n",c1_length);
    uint8_t c1_serialized[c1_length];
    hex_string_to_byte_array(c1_serialized_hex, c1_serialized, c1_length);

    printf("Enter C2 data in hex format: ");
    scanf("%1023s", c2_hex);
    m_length = strlen(c2_hex) / 2;
    printf("\nm_length is : %d\n",m_length);
    uint8_t c2[m_length];
    hex_string_to_byte_array(c2_hex, c2, m_length);

    printf("Enter C3 data in hex format: ");
    scanf("%1023s", c3_hex);
    m_length = strlen(c3_hex) / 2;
    printf("\nm_length is : %d\n",m_length);
    uint8_t c3[m_length];
    hex_string_to_byte_array(c3_hex, c3, m_length);

    // Deserialize 'c1'
    g1_t c1;
    g1_read_bin(c1, c1_serialized, c1_length); 

    // Display 'c1' as hexadecimal
    printf("\nSerialized c1 in hex format is: ");
    for (int i = 0; i < c1_length; i++) {
        printf("%02X", c1_serialized[i]);
    }
    printf("\n");

    printf("C1 in G2 is:\n");
    g1_print(c1);
    printf("\n");

    printf("\nEncrypted data C2 is: ");
    for (int i = 0; i < m_length; i++) {
        printf("%02X", c2[i]);
    }
    printf("\n");

    printf("\nEncrypted data C3 is: ");
    for (int i = 0; i < m_length; i++) {
        printf("%02X",c3[i]);
    }
    printf("\n");



    // Extract private key and decrypt
    g2_t d_ID;
    g2_new(d_ID);
    uint8_t ID[] = "user@domain.com"; //This must be the same in both encyrption and decryption codes!!!!!
    extract_private_key(d_ID, ID, strlen((char *)ID), s);
    
    uint8_t decrypted[m_length];

    printf("\n");

    // Measure time and memory for decryption
    clock_t start_decryption = clock(); // should extract private key be measured in the decryption time?


    // Decrypt

    int success = decrypt(decrypted, c1, c2, c3, d_ID, m_length);

    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_decryption = clock();

    if (success) {
        printf("Decrypted Message: %s\n", decrypted);
    } else {
        printf("Decryption failed!\n");
    }




    printf("Decryption Time: %f seconds\n", ((double) (end_decryption - start_decryption)) / CLOCKS_PER_SEC);



  // Cleanup
    g1_free(c1);
    g2_free(d_ID);
    core_clean();
    return 0;
}

