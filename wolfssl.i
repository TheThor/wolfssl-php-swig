%typemap(in) const byte* {
  if (Z_TYPE_P($input) == IS_STRING) {
    char *str = Z_STRVAL_P($input);
    size_t len = Z_STRLEN_P($input);
    $1 = (const byte*) str;
    $1_len = (word32) len;
  } else {
    SWIG_PHP_Error(E_ERROR, "Expected a string");
    return;
  }
}

%module wolfssl

%{
    #include <wolfssl/wolfssl/ssl.h>
    #include <wolfssl/wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/wolfssl/options.h>
    #include <wolfssl/wolfssl/wolfcrypt/signature.h>
    #include <wolfssl/wolfcrypt/pwdbased.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/types.h>

    char* wolfSSL_error_string(int err);
    int   wolfSSL_swig_connect(WOLFSSL*, const char* server, int port);
    WC_RNG* GetRng(void);
    RsaKey* GetRsaPrivateKey(const char* file);
    void    FillSignStr(unsigned char*, const char*, int);

%}


WOLFSSL_METHOD*  wolfSSLv23_client_method(void);
WOLFSSL_METHOD*  wolfSSLv23_server_method(void);

WOLFSSL_CTX*     wolfSSL_CTX_new(WOLFSSL_METHOD*);
int              wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX*, const char*, const char*);
WOLFSSL*         wolfSSL_new(WOLFSSL_CTX*);
int              wolfSSL_get_error(WOLFSSL*, int);
int              wolfSSL_write(WOLFSSL*, const char*, int);
int              wolfSSL_Debugging_ON(void);
int              wolfSSL_Init(void);
int              wolfSSL_use_certificate_buffer(WOLFSSL* ssl, char* in, long sz, int format);
int              wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, char* in, long sz, int format);
int              ProcessBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff, long sz, int format, int type, WOLFSSL* ssl, long* used, int userChain, int verify);
int              wc_SignatureGenerate(enum wc_HashType hash_type, enum wc_SignatureType sig_type, const byte* data, word32 data_len, byte* sig, word32 *sig_len, const void* key, word32 key_len, WC_RNG* rng);


int              wc_PKCS12_PBKDF(unsigned char* output, const unsigned char* passwd, int pLen, const unsigned char* salt,
                           int sLen, int iterations, int kLen, int hashType, int purpose);
int              wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key, WC_RNG* rng);
int              wc_RsaSSL_Verify(const byte* in, int inLen, unsigned char* out, int outLen, RsaKey* key);