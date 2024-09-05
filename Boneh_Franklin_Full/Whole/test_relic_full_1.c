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


// Define global variables and parameters
g1_t P1, Ppub; // P1->generator of G1, Ppub->Publuc Key
g2_t  P2, d_ID ; // 
bn_t s, p; //s->Master Secret, p->order of a group (G1 or G2)

//H1

void H1(g2_t out, uint8_t *in, int len) {
    //uint8_t hash[HASH_OUTPUT_SIZE];
    //md_map(hash, in, len);
    //g2_map(out, in, HASH_OUTPUT_SIZE);
    g2_map(out, in, len);
}

//H2   

void H2(uint8_t *hash, gt_t in, int len) {
    int size = gt_size_bin(in, 0);
    //gia na ftiaxw buffer pou xwraei oso megalo kai na einai to input tha kanw:
    //int a = len(megethos message(gia to arxiko use ths H2 opou einai kai to thema..)) / size . 
    // kai tha prosthesw sto buufer size -> buffer[size+size*a]    opou an to a einai 0 eimaste ok!
    int a = len/size;
    //uint8_t buffer[size];
    int b=size+a*size;
    //uint8_t buffer[a];
    // TELIKA TO SWSTO EINAI ME MALLOC!!! OMG!! (OLA TA PANW EINAI LATHOS!)
    //uint8_t *buffer = (uint8_t *)malloc((1+a) * RLC_FP_BYTES);
    uint8_t *buffer = (uint8_t *)malloc(len);    
    if (buffer == NULL) {
    // Handle memory allocation failure
    printf("Memory allocation failed.\n");
    free(buffer);
    return;
    }
    //printf("\na is: %d \n", a);
    //printf("\nsize is: %d \n", size);
    //printf("\nsize is: %d \n", len);

    gt_write_bin(buffer, size, in, 0);
    //gt_write_bin(buffer, size, in, 0);
    md_map(hash, buffer, len);
    //md_map(hash, buffer, HASH_OUTPUT_SIZE);

    free(buffer);

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
/*
    // Step 2: Adjust the length of the output
    if (m_length <= HASH_OUTPUT_SIZE) {
        // Truncate if m_length is less than or equal to the hash function output size
        memcpy(output, hash, m_length);
    } else {
        // Pad if m_length is greater than the hash function output size
        // Simple padding example: repeat the hash as needed
        for (int i = 0; i < m_length; i++) {
            output[i] = hash[i % HASH_OUTPUT_SIZE];
        }
    }
}*///////

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

void encrypt(uint8_t *ID, uint8_t *M, int m_length, g1_t C1, uint8_t *C2, uint8_t *C3) {

    // Memory profiling variables
    struct rusage r_usage_start, r_usage_end;
    long memory_usage_start, memory_usage_end;
    
    // Start memory profiling
    getrusage(RUSAGE_SELF, &r_usage_start);
    memory_usage_start = r_usage_start.ru_maxrss ;
  //  printf("Memory usage-encrypt start: %ld KB\n", memory_usage_start);
    //

    
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

    // End memory profiling
    getrusage(RUSAGE_SELF, &r_usage_end);
    memory_usage_end = r_usage_end.ru_maxrss ;
    printf("Memory usage-encrypt end: %ld KB\n", memory_usage_end);


//**************************************
    // Cleanup
    g2_free(Q_ID);
    bn_free(r);
}

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
    memory_usage_start = r_usage_start.ru_maxrss;
    printf("Memory usage-decrypt start: %ld KB\n", memory_usage_start);
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
   
    printf("\nnewC1 is:\n");
    g1_print(newC1);
    printf("\n");
    printf("\nDecrypted Message: %s\n", M);

    if (g1_cmp(C1, newC1) != RLC_EQ){
        printf("\nThe decryption is rejected! :'(\n");
        return 0;
    } else {
        printf("\nThe decryption is perfect!! :-*\n");
    }
    


    // End memory profiling
    getrusage(RUSAGE_SELF, &r_usage_end);
    memory_usage_end = r_usage_end.ru_maxrss;
    printf("Memory usage-decrypt end: %ld KB\n", memory_usage_end);

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
    // Initialize RELIC and setup system parameters
        // Initialize RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }
    pc_param_set_any();
//    ep_param_set(B12_P638); // Barreto-Lynn-Scott sec->160bits 
//    ep_param_set(B12_P377); // Barreto-Lynn-Scott sec->128bits 
//    ep_param_set(B12_P381); // Barreto-Lynn-Scott sec->128bits 

    //ep_param_set(SG18_P638); //not implemented!!
    ep_param_set(K18_P638); // Kachisa-Scott-Schaefer sec->192bits 

//    ep_param_set(BN_P638); // Barreto-Naehrig sec->160bits 
//    ep_param_set(BN_P254); // Barreto-Naehrig sec->120bits 
//    ep_param_set(BN_P256); // Barreto-Naehrig sec->120bits 
//    ep_param_set(BN_P158); // Barreto-Naehrig sec->78bits 
   


    pc_param_print();
    printf("\n");
    ep_param_print();


    //Setup
    setup();

    // Message and its length
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA  MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA"; //(issue corrected!) up to 32 Bytes? Why in some numbers above 32 it is working?? (problems:40,37,36,35,34,33)
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSA  MomomomomoSKOUPAARIBAARI  -hahagsagjhjhfgdkajkjhfbsba-  BamoSmomomoSAMomomomomoSKOUPAARIBAARI   -hahagsagjhjhfgdkajkjhfbsba--hahagsagjhjhfgdkajkjhfbsba--hahagsagjhjhf12";  
    uint8_t message[] = "YOLO";
    //uint8_t message[] = "Hello, FullIdent!";
    //uint8_t message[] = "MomomomomoSKOUPAARIBAARI kjaskjaskh asasadadoAARI kjaskjaskh asasadadoAARI kjaskjaskh asasadadoAARI kjaskjaskh asasadado"; //(issue corrected!) up to 32 Bytes? Why in some numbers above 32 it is working?? (problems:40,37,36,35,34,33)

    int message_length = strlen((char *)message);
    printf("\nmessage_length = %d\n", message_length);

    // Ciphertext components

    g1_t C1;
    uint8_t C2[sizeof(message)];
    uint8_t C3[sizeof(message)];
    g1_new(C1);



    // Identity ID
    uint8_t ID[] = "user@domain.com";

    // Extract private key
    extract_private_key(d_ID, ID, strlen((char *)ID), s);

    // Measure time and memory for encryption
    clock_t start_encryption = clock();
    //size_t memory_before_encryption = malloc_usable_size(NULL);
   

    // Encrypt
    encrypt(ID, message, message_length, C1, C2, C3);


    //size_t memory_after_encryption = malloc_usable_size(NULL);
    clock_t end_encryption = clock();

    // Measure time and memory for decryption
    clock_t start_decryption = clock();
    //size_t memory_before_decryption = malloc_usable_size(NULL);



    // Decrypt
    uint8_t decrypted[sizeof(message)];
    int success = decrypt(decrypted, C1, C2, C3, d_ID, message_length);

    if (success) {
        printf("Original Message: %s\n", message);
        printf("Decrypted Message: %s\n", decrypted);
    } else {
        printf("Decryption failed!\n");
    }

    //size_t memory_after_decryption = malloc_usable_size(NULL);
    clock_t end_decryption = clock();

    // Print timing results
    printf("Encryption Time: %f seconds\n", ((double) (end_encryption - start_encryption)) / CLOCKS_PER_SEC);
    printf("Decryption Time: %f seconds\n", ((double) (end_decryption - start_decryption)) / CLOCKS_PER_SEC);

 

    // Cleanup
    g1_free(C1);
    g2_free(d_ID);

    // Cleanup RELIC
    core_clean();

    return 0;
}       














/******************************************************************

void setup() {
    // Initialize
    core_init();

    // Initialize pairing
    pairing_t pairing;
    if (pairing_init_set_str(pairing, param) == RLC_ERR) {
        core_clean();
        return;
    }

    // Initialize variables
    g1_new(P1);
    g2_new(G2);
    g1_new(Ppub);
    bn_new(s);
    bn_new(p);

    // Setup the system parameters and master key
    pc_param_set_any();
    g1_get_gen(P1);
    g2_get_gen(G2);
    g1_mul(Ppub, P1, s); // Ppub = s * P1

    // Initialize private key d_ID
    g1_new(d_ID);
}

void H1(g2_t Q_ID, uint8_t *ID, int ID_length) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(ID, ID_length, hash); // Compute SHA-256 hash of ID
    g2_from_bin(Q_ID, hash, SHA256_DIGEST_LENGTH); // Convert the hash to a G2 element
}

void hash_g2(uint8_t *output, g2_t element) {
    // Convert the G2 element to a byte array
    uint8_t bin[2 * RLC_FP_BYTES];
    g2_write_bin(bin, sizeof(bin), element, 1);

    // Compute SHA-256 hash of the byte array
    SHA256(bin, sizeof(bin), output);
}

void extract_private_key(uint8_t *ID, int ID_length) {
    g2_t Q_ID;

    // Initialize variables
    g2_new(Q_ID);

    // Extract private key d_ID
    H1(Q_ID, ID, ID_length);
    g2_mul(d_ID, Q_ID, s);

    // Cleanup
    g2_free(Q_ID);
}

void encrypt(uint8_t *ID, uint8_t *M, int M_length, g2_t C1, gt_t C2, gt_t C3) {
    g2_t Q_ID;
    bn_t r;
    uint8_t sigma[M_length];

    // Initialize variables
    g2_new(Q_ID);
    bn_new(r);

    // Compute Q_ID = H1(ID)
    H1(Q_ID, ID, strlen((char *)ID));

    // Choose a random string sigma with length M_length
    // (In practice, you'd use a secure random number generator)
    // Here, for simplicity, we generate a random sigma of the same length as M
    bn_rand_mod(r, p);
    g2_mul(C1, P1, r); // C1 = r * P1

    // Compute gID = e(Ppub, Q_ID) in GT
    gt_t g_ID;
    pc_map(g_ID, Ppub, Q_ID);

    // Compute sigma = M XOR H2(g_ID)
    gt_exp(g_ID, g_ID, r); // g_ID = g_ID^r
    hash_g2(sigma, g_ID);   // H2(g_ID)

    // Set ciphertext components
    gt_new(C2);
    gt_new(C3);
    gt_set_str(C2, (char *)sigma, M_length);
    gt_set_str(C3, (char *)M, M_length);

    // Cleanup
    g2_free(Q_ID);
    bn_free(r);
}

int decrypt(g2_t C1, gt_t C2, gt_t C3, uint8_t *ID, uint8_t *M, int M_length) {
    g2_t Q_ID;
    uint8_t sigma[M_length];

    // Initialize variables
    g2_new(Q_ID);

    // Compute Q_ID = H1(ID)
    H1(Q_ID, ID, strlen((char *)ID));

    // Compute g_ID = e(C1, d_ID) in GT
    gt_t g_ID;
    pc_map(g_ID, C1, d_ID);

    // Compute sigma = C2 XOR H2(g_ID)
    gt_exp(g_ID, g_ID, bn_zero); // g_ID = g_ID^0 = 1
    hash_g2(sigma, g_ID);        // H2(g_ID)

    // Check if C1 is valid
    if (g1_cmp(C1, P1) != RLC_EQ) {
        printf("Invalid ciphertext\n");
        return 0;
    }

    // Compute M = C3 XOR H4(sigma)
    for (int i = 0; i < M_length; i++) {
        M[i] = C3[i] ^ sigma[i];
    }

    // Cleanup
    g2_free(Q_ID);

    return 1;
}

int main(void) {
    // Initialize RELIC and setup system parameters
    setup();

    // Identity ID
    uint8_t ID[] = "user@domain.com";

    // Extract private key
    extract_private_key(ID, strlen((char *)ID));

    // Message and its length
    uint8_t message[] = "Hello, FullIdent!";
    int message_length = strlen((char *)message);

    // Ciphertext components
    g2_t C1;
    gt_t C2, C3;
    g2_new(C1);
    gt_new(C2);
    gt_new(C3);

    // Encrypt
    encrypt(ID, message, message_length, C1, C2, C3);

    // Decrypt
    uint8_t decrypted[message_length];
    int success = decrypt(C1, C2, C3, ID, decrypted, message_length);

    if (success) {
        printf("Original Message: %s\n", message);
        printf("Decrypted Message: %s\n", decrypted);
    } else {
        printf("Decryption failed!\n");
    }

    // Cleanup
    g2_free(C1);
    gt_free(C2);
    gt_free(C3);
    g2_free(d_ID);

    // Cleanup RELIC
    core_clean();

    return 0;
}       


**********************************/
