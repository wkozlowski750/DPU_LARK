// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdint.h>

// #include <openssl/crypto.h>
// #include <openssl/engine.h>

// #include <time.h>
            

// ENGINE *e;
// const char *doca_engine_path = "/opt/mellanox/doca/infrastructure/doca_sha_offload_engine/libdoca_sha_offload_engine.so";
// const char *default_doca_pci_addr = "03:00.0";
// ENGINE_load_dynamic();
// e = ENGINE_by_id(doca_engine_path);
// // ENGINE_ctrl_cmd_string(e, "set_pci_addr", doca_engine_pci_addr, 0);
// ENGINE_init(e);
// ENGINE_set_default_digests(e);


// long long calculate_elapsed_time_ns(struct timespec start, struct timespec end) {
//     return (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
// }

// struct timespec start;
// struct timespec stop;
// int main(int argc, char * argv[]) {

//     if (argc < 2) {
//         printf("Need number of bytes\n");
//         return -1;
//     }

//     int bytes = atoi(argv[1]);

//     char data[bytes+1];

//     data[bytes] = '\0';
//     memset(data, 'A', bytes);
//     unsigned char digest[33];

//     if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
//         printf("Couldn't get start time\n");
//         return -1;
//     }

//     const EVP_MD *evp_md = EVP_sha256();
//     EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
//     EVP_DigestInit_ex(mdctx, evp_md, e);
//     EVP_DigestUpdate(mdctx, data, bytes);
//     EVP_DigestFinal_ex(mdctx, digest, 32);


//     if (clock_gettime(CLOCK_MONOTONIC, &stop) != 0) {
//         printf("Couldn't get stop time\n");
//         return -1;
//     }

//     long long diff = calculate_elapsed_time_ns(start, stop);

//     printf("hash time: %lld", diff);

//     printf("Sha256 dgst: ");
//     for (int i = 0; i < 32; i++) {
//         printf("%x", digest[i]);
//     }
//     printf("\n");

//     EVP_MD_CTX_destroy(mdctx);


//     return 0;
// }
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

long long calculate_elapsed_time_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Need number of bytes\n");
        return -1;
    }

    int bytes = atoi(argv[1]);
    if (bytes <= 0) {
        printf("Number of bytes must be positive\n");
        return -1;
    }

    // Dynamic Engine Loading
    ENGINE_load_dynamic();

    const char *doca_engine_path = "doca_sha_offload_engine";
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!e) {
        printf("Engine dynamic loading failed\n");
        return -1;
    }

    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "/opt/mellanox/doca/infrastructure/doca_sha_offload_engine/libdoca_sha_offload_engine.so", 0)
        || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)
        || !ENGINE_ctrl_cmd_string(e, "set_pci_addr", "03:00.0", 0)) {
        printf("Engine configuration failed\n");
        ENGINE_free(e);
        return -1;
    }

    if (!ENGINE_init(e)) {
        printf("Engine initialization failed\n");
        ENGINE_free(e);
        return -1;
    }

    ENGINE_set_default_digests(e);

    char *data = malloc(bytes);
    if (!data) {
        printf("Memory allocation failed\n");
        ENGINE_finish(e);
        ENGINE_free(e);
        return -1;
    }
    memset(data, 'A', bytes);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    struct timespec start, stop;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        printf("Couldn't get start time\n");
        free(data);
        ENGINE_finish(e);
        ENGINE_free(e);
        return -1;
    }

    // Digest operations
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *evp_md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, evp_md, e);
    EVP_DigestUpdate(mdctx, data, bytes);
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    EVP_MD_CTX_free(mdctx);

    if (clock_gettime(CLOCK_MONOTONIC, &stop) != 0) {
        printf("Couldn't get stop time\n");
        free(data);
        ENGINE_finish(e);
        ENGINE_free(e);
        return -1;
    }

    long long diff = calculate_elapsed_time_ns(start, stop);
    printf("Hash time: %lld ns\n", diff);

    FILE *fp = fopen("benchmark_times.txt", "a"); // Open the file in append mode
    if (fp == NULL) {
        perror("Failed to open file");
        EVP_MD_CTX_free(mdctx);
        free(data);
        return 1;
    }
    fprintf(fp, "%d,%lld\n", bytes, diff);
    fclose(fp); // Close the file

    printf("SHA-256 digest: ");
    for (unsigned int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free(data);
    ENGINE_finish(e);
    ENGINE_free(e);

    return 0;
}
