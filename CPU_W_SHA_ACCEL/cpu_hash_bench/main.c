#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <time.h>

// Function to calculate elapsed time in nanoseconds
long long calculate_elapsed_time_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <number of bytes>\n", argv[0]);
        return 1;
    }

    int bytes = atoi(argv[1]);
    if (bytes <= 0) {
        fprintf(stderr, "Number of bytes must be positive\n");
        return 1;
    }

    // Allocate memory for the data
    char *data = malloc(bytes);
    if (!data) {
        perror("Failed to allocate memory");
        return 1;
    }

    // Fill the data with 'A'
    memset(data, 'A', bytes);

    // Initialize OpenSSL digest context
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    struct timespec start, stop;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        free(data);
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        return 1;
    }

    // Measure the time taken to compute the SHA-256 hash
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("Failed to get start time");
        EVP_MD_CTX_free(mdctx);
        free(data);
        return 1;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, bytes);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    if (clock_gettime(CLOCK_MONOTONIC, &stop) != 0) {
        perror("Failed to get stop time");
        EVP_MD_CTX_free(mdctx);
        free(data);
        return 1;
    }

    long long diff = calculate_elapsed_time_ns(start, stop);

    printf("Time taken for hashing %d bytes: %lld ns\n", bytes, diff);
    FILE *fp = fopen("benchmark_times.txt", "a"); // Open the file in append mode
    if (fp == NULL) {
        perror("Failed to open file");
        EVP_MD_CTX_free(mdctx);
        free(data);
        return 1;
    }
    fprintf(fp, "%d,%lld\n", bytes, diff);
    fclose(fp); // Close the file


    // Print the SHA-256 hash in hexadecimal
    printf("SHA-256 digest: ");
    for (unsigned int i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    EVP_MD_CTX_free(mdctx);
    free(data);
    return 0;
}
