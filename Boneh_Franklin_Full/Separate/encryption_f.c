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

//bn_print

void print_bn(bn_t num) {
    int length = bn_size_str(num, 10);
    char str[length];
    bn_write_str(str, length, num, 10);
    printf("%s\n", str);
}

//Setup

void setup() {
    // Initialize
    g1_new(P1);
    g1_new(Ppub);
    g2_new(P2);
    bn_new(p);
    bn_new(s);

    // Setup the pairing-friendly curve
    //ep_param_set_any();

    // Get the group generators
    g1_get_gen(P1); 
    printf("\nG1 gen is:\n");
    g1_print(P1);
    g2_get_gen(P2);
    printf("\nG2 gen is:\n");
    g2_print(P2);
    // Get the order of the group
    g1_get_ord(p);

    // Generate a random master secret
    bn_rand_mod(s, p);

    // Compute the public key
    g1_mul(Ppub, P1, s);
}

//Encrypt

void encrypt(uint8_t *ID, uint8_t *M, int m_length, g1_t C1, uint8_t *C2, uint8_t *C3) {
    g2_t Q_ID;
    bn_t r;
    uint8_t hash_of_gIDr[HASH_OUTPUT_SIZE];
    uint8_t hash_of_sigma[HASH_OUTPUT_SIZE];
    uint8_t sigma[m_length]; //we will generate random bytes in here
    char sigma_string[m_length+1]; //we will convert random bytes to ASCII and add '\0' null character to get a string!
    //our actual sigma is sigma!!! sigma_string is just for checking!
    // Initialize variables
    g2_new(Q_ID);
    bn_new(r);      

    // Compute Q_ID = H1(ID)
    H1(Q_ID, ID, strlen((char *)ID)); // if wrong try strlen(ID) ?

    // Choose a random string sigma with length M_length
    // (In practice, you'd use a secure random number generator)
    // Here, for simplicity, we generate a random sigma of the same length as M
    // Generate random bytes
    rand_bytes(sigma, m_length);

    // Convert to a string (assuming ASCII values)
    for (int i = 0; i < m_length; i++) {
        // Ensure each byte is a printable ASCII character
        sigma_string[i] = (sigma[i] % 95) + 32; // ASCII range 32 to 126
    }
    sigma_string[m_length]='\0' ; //strlen(sigma_string)=m_length

    printf("\nRandom sigma is: %s\n",sigma_string);

    H3(r, sigma, M, m_length);

    g1_mul(C1, P1, r); // C1 = r * P1  , P1:generator of G1
    
    printf("\nC1 is:\n");
    g1_print(C1);
    printf("\n");

    // Compute gID = e(Ppub, Q_ID) in GT
    gt_t g_ID;
    pc_map(g_ID, Ppub, Q_ID);

    // Compute sigma = M XOR H2(g_ID)
    gt_exp(g_ID, g_ID, r); // g_ID = g_ID^r
    H2(hash_of_gIDr, g_ID, m_length);   // H2(g_ID^r)

   // *********** THE FOLLOWING IS IN ORDER TO HAVE CORRECT ENCRYPTION FOR MESSAGES BIGGER THATN HASH_OUTPUT_SIZE!!!****


    if (m_length<HASH_OUTPUT_SIZE){
        // Set C2 components
        for (int i = 0; i < m_length; i++) {
            C2[i] = sigma[i] ^ hash_of_gIDr[i];
        }  

        //compute H4(sigma)
        H4(hash_of_sigma, sigma, m_length);
        
        // Set C3 components
        for (int i = 0; i < m_length; i++) {
            C3[i] = M[i] ^ hash_of_sigma[i];
        }  
    }else{
        // Set C2 components
        for (int i = 0; i < HASH_OUTPUT_SIZE; i++) {
            C2[i] = sigma[i] ^ hash_of_gIDr[i];
        }  
        for (int i = HASH_OUTPUT_SIZE; i < m_length; i++) {
            C2[i] = sigma[i];
        } 

        //compute H4(sigma)
        H4(hash_of_sigma, sigma, m_length);
        
        // Set C3 components
        for (int i = 0; i < HASH_OUTPUT_SIZE; i++) {
            C3[i] = M[i] ^ hash_of_sigma[i];
        }
        for (int i = HASH_OUTPUT_SIZE; i < m_length; i++) {
            C3[i] = M[i];
        }
    }
//**************************************
    // Cleanup
    g2_free(Q_ID);
    bn_free(r);
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
   // ep_param_print();
    printf("\n");


    // Setup global parameters
    setup();

    // Identity and message
    uint8_t ID[] = "user@domain.com"; //This must be the same in both encyrption and decryption codes!!!!!
    uint8_t message[] = "Hello, FullIdent!";
    //uint8_t message[] = "Hello, FullIdent MOomammsmoaomsaom jahgshag uaysaysub !!!! -- !!";

    //int message_length = sizeof(message);
    int message_length = strlen((char *)message);

    // Ciphertext components
    g1_t C1;
    uint8_t C2[sizeof(message)], C3[sizeof(message)];
    g1_new(C1);

    // Measure time and memory for decryption
    clock_t start_encryption = clock();
    //size_t memory_before_decryption = malloc_usable_size(NULL);


    // Encrypt the message
    encrypt(ID, message, message_length, C1, C2, C3);

    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_encryption = clock();

    // Serialize and print C1
    int c1_size = g1_size_bin(C1, 0);
    uint8_t *c1_serialized = malloc(c1_size * sizeof(uint8_t));
    g1_write_bin(c1_serialized, c1_size, C1, 0);
    printf("C1: ");
    for (int i = 0; i < c1_size; i++) {
        printf("%02X", c1_serialized[i]);
    }
    printf("\n");

    // Print C2
    printf("C2: ");
    for (int i = 0; i < message_length; i++) {
        printf("%02X", C2[i]);
    }
    printf("\n");

    // Print C3
    printf("C3: ");
    for (int i = 0; i < message_length; i++) {
        printf("%02X", C3[i]);
    }
    printf("\n");



    //secret s is printed in order for decryption program to create private key (d_ID)
    printf("\nSecret s: ");
    
    print_bn(s);
    printf("\n");

    printf("Encryption Time: %f seconds\n", ((double) (end_encryption - start_encryption)) / CLOCKS_PER_SEC);


    free(c1_serialized);

    
/**************
    // Output encrypted data
    printf("Encrypted data:\nC1: ");
    g1_print(C1);
    printf("\nC2: ");
    for (int i = 0; i < message_length; i++) printf("%02X", C2[i]);
    printf("\nC3: ");
    for (int i = 0; i < message_length; i++) printf("%02X", C3[i]);
    printf("\n");
**************/
    // Cleanup
    g1_free(C1);
    core_clean();
    return 0;
}

// Implement setup(), H1(), H2(), H3(), H4(), and encrypt() here...
