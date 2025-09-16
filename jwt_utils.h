#pragma once
#include <string>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>
#include <vector>

struct KeyPair {
    std::string kid;
    RSA* rsa;
    time_t expires;
};

// Helper: generate a new RSA key pair
inline KeyPair generateKey(const std::string& kid, int expiry_seconds) {
    KeyPair kp;
    kp.kid = kid;
    kp.rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(kp.rsa, 2048, e, nullptr);
    BN_free(e);
    kp.expires = time(nullptr) + expiry_seconds;
    return kp;
}

// Helper: convert RSA public key to JWKS n/e (base64 url)
inline std::string base64UrlEncode(const unsigned char* input, int length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string s(bptr->data, bptr->length);
    BIO_free_all(b64);
    // URL-safe
    for (auto &c : s) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    return s;
}

// Helper: simple function to convert RSA key to n/e
inline std::pair<std::string,std::string> getPublicKeyComponents(RSA* rsa) {
    const BIGNUM* n; const BIGNUM* e;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    n = rsa->n; e = rsa->e;
#else
    RSA_get0_key(rsa, &n, &e, nullptr);
#endif
    int nLen = BN_num_bytes(n);
    int eLen = BN_num_bytes(e);
    std::vector<unsigned char> nBuf(nLen);
    std::vector<unsigned char> eBuf(eLen);
    BN_bn2bin(n, nBuf.data());
    BN_bn2bin(e, eBuf.data());
    return { base64UrlEncode(nBuf.data(), nLen), base64UrlEncode(eBuf.data(), eLen) };
}

// Helper: sign a JWT using RS256
inline std::string signJWT(const KeyPair& kp, const std::string& payload) {
    std::string header = R"({"alg":"RS256","typ":"JWT","kid":")" + kp.kid + "\"}";
    auto base64Encode = [](const std::string& str){
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO* mem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, mem);
        BIO_write(b64, str.c_str(), str.size());
        BIO_flush(b64);
        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string out(bptr->data, bptr->length);
        BIO_free_all(b64);
        for (auto &c : out) { if (c == '+') c='-'; else if(c=='/') c='_'; }
        return out;
    };
    std::string message = base64Encode(header) + "." + base64Encode(payload);
    unsigned char sig[256];
    unsigned int sigLen;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, kp.rsa); // ownership transferred
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, message.c_str(), message.size());
    EVP_SignFinal(ctx, sig, &sigLen, pkey);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return message + "." + base64Encode(std::string((char*)sig, sigLen));
}
