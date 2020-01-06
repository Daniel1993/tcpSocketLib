#include "tcpSocketLib.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define ECC_CURVE            NID_secp521r1
#define HASH_TYPE            EVP_sha512()
#define HASH_SIZE            SHA512_DIGEST_LENGTH
#define SIGN_TYPE            HASH_TYPE
#define SYM_KEY_SIZE         1024
#define SIGN_SIZE            SYM_KEY_SIZE
#define INTERNAL_BUFFER_SIZE (SYM_KEY_SIZE<<1)
#define CERT_BUFFER_SIZE     (INTERNAL_BUFFER_SIZE<<3)
#define ECC_KEY_T(_var)      byte _var[INTERNAL_BUFFER_SIZE<<2] // TODO: their ecc_key type is broken

#define INIT_ERROR_CHECK() \
  intptr_t _err; \
//
#define ERROR_CHECK(call, teardown) \
_err = (intptr_t)(call); \
if (_err == 0 || _err == -1) { \
  BIO *_bio = BIO_new(BIO_s_mem()); \
  char *_sslError; \
  ERR_print_errors(_bio); \
  BIO_get_mem_data(_bio, &_sslError); \
  TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, _sslError); \
  teardown; \
} \
//

static EVP_PKEY *loadedPrivKey = NULL;
static X509 *loadedCert = NULL;
static EVP_PKEY *loadedPublKey = NULL; // this should be a x509 cert
static unsigned char loadedSimKey[HASH_SIZE];
static unsigned char loadedIV[HASH_SIZE];

#define GET_SECRET_LEN(_eckey) \
  ((EC_GROUP_get_degree(EC_KEY_get0_group(_eckey)) + 7) / 8) \
// ECDH_size(_eckey)
//

static void *negotiatedKeys[TSL_MAX_SECRETS];
static size_t negotiatedKeysSize = 0;

int tsl_create_keys(char *privkey, char *publkey, char *publkeyCsr, tsl_csr_fields_t fields)
{
  EC_KEY *ecc;
  EVP_PKEY *pkey;
  X509_REQ *x509_req;
  X509_NAME *x509_name;
  FILE *privkey_fp, *publkey_fp, *publkeyCsr_fp;
  INIT_ERROR_CHECK();

  ecc = EC_KEY_new_by_curve_name(ECC_CURVE);
  EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

  ERROR_CHECK(EC_KEY_generate_key(ecc), { return -1; });
  pkey = EVP_PKEY_new();
  ERROR_CHECK(EVP_PKEY_assign_EC_KEY(pkey, ecc), { return -1; });
  ecc = EVP_PKEY_get1_EC_KEY(pkey);

  if ((privkey_fp = fopen(privkey, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(PEM_write_PrivateKey(privkey_fp, pkey, NULL, NULL, 0, 0, NULL), { return -1; });

  if ((publkey_fp = fopen(publkey, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(PEM_write_PUBKEY(publkey_fp, pkey), { return -1; });

  x509_req = X509_REQ_new();
  ERROR_CHECK(X509_REQ_set_version(x509_req, 1 /* version */), { return -1; });
  x509_name = X509_REQ_get_subject_name(x509_req);
  X509_NAME_add_entry_by_txt(x509_name, "C" , MBSTRING_ASC, (const unsigned char*)fields.country, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, (const unsigned char*)fields.state, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "L" , MBSTRING_ASC, (const unsigned char*)fields.locality, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char*)fields.commonName, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "O" , MBSTRING_ASC, (const unsigned char*)fields.org, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, (const unsigned char*)fields.unit, -1, -1, 0);

  ERROR_CHECK(X509_REQ_set_pubkey(x509_req, pkey), { return -1; });
  ERROR_CHECK(X509_REQ_sign(x509_req, pkey, SIGN_TYPE), { return -1; });

  if ((publkeyCsr_fp = fopen(publkeyCsr, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(PEM_write_X509_REQ_NEW(publkeyCsr_fp, x509_req), { return -1; });

  fclose(privkey_fp);
  fclose(publkey_fp);
  fclose(publkeyCsr_fp);

  EVP_PKEY_free(pkey);
  EC_KEY_free(ecc);
  X509_REQ_free(x509_req);

  return 0;
}

int tsl_load_privkey(char *privkey)
{
  int ret = -1;
  FILE *privkey_fp;
  INIT_ERROR_CHECK();
  
  if (loadedPrivKey == NULL) {
    EVP_PKEY_free(loadedPrivKey);
  }
  if ((privkey_fp = fopen(privkey, "rb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK((loadedPrivKey = PEM_read_PrivateKey(privkey_fp, NULL, NULL, NULL)), { goto ret; });
  
  if (loadedPublKey != NULL) {
    EVP_PKEY_free(loadedPublKey);
  }
  loadedPublKey = EVP_PKEY_new();
  EC_KEY *pubkey = EVP_PKEY_get1_EC_KEY(loadedPrivKey);
  ERROR_CHECK(EVP_PKEY_assign_EC_KEY(loadedPublKey, pubkey), { goto ret; });
  
  ret = 0;
ret:
  fclose(privkey_fp);
  return ret;
}

int tsl_load_publkey(char *publFile)
{
  FILE *publkey_fp;
  INIT_ERROR_CHECK();
  int ret = -1;
  
  if (loadedPublKey == NULL) {
    EVP_PKEY_free(loadedPublKey);
  }
  if ((publkey_fp = fopen(publFile, "rb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK((loadedPublKey = PEM_read_PUBKEY(publkey_fp, NULL, NULL, NULL)), { goto ret; });

  ret = 0;
ret:
  fclose(publkey_fp);
  return ret;
}

// TODO: chain cert
int tsl_load_cert(char *cert)
{
  FILE *cert_fp;
  INIT_ERROR_CHECK();
  
  if ((cert_fp = fopen(cert, "rb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  if (loadedCert != NULL) {
    X509_free(loadedCert);
  }
  ERROR_CHECK(loadedCert = PEM_read_X509(cert_fp, NULL, NULL, NULL), { return -1; });
  fclose(cert_fp);

  // crt_subject = X509_REQ_get_subject_name(x509_req);
  
  if (loadedPublKey != NULL) {
    EVP_PKEY_free(loadedPublKey);
  }
  loadedPublKey = X509_get_pubkey(loadedCert);

  return 0;
}

static void copy_to_str_end(char *src, char *dst)
{
  char *c = src;
  int i = 0;
  while (!(*c == '/' || *c == '\0')) {
    dst[i++] = *c;
    c++;
  }
  dst[i++] = '\0';
}

static void copy_to_fields(char *str, tsl_csr_fields_t *fields)
{
  char *s = str;

  while (*s != '\0') {
    if ((s[0] == '/') && (s[1] == 'C') && (s[2] == '='))
    {
      s += 3;
      copy_to_str_end(s, fields->country);
    }
    else if ((s[0] == '/') && (s[1] == 'L') && (s[2] == '='))
    {
      s += 3;
      copy_to_str_end(s, fields->locality);
    }
    else if ((s[0] == '/') && (s[1] == 'O') && (s[2] == '='))
    {
      s += 3;
      copy_to_str_end(s, fields->org);
    }
    else if ((s[0] == '/') && ((s[1] == 'S') && (s[2] == 'T')) && (s[3] == '='))
    {
      s += 4;
      copy_to_str_end(s, fields->state);
    }
    else if ((s[0] == '/') && ((s[1] == 'C') && (s[2] == 'N')) && (s[3] == '='))
    {
      s += 4;
      copy_to_str_end(s, fields->commonName);
    }
    else if ((s[0] == '/') && ((s[1] == 'O') && (s[2] == 'U')) && (s[3] == '='))
    {
      s += 4;
      copy_to_str_end(s, fields->unit);
    }
    else
    {
      s++;
    }
  }
}

int tsl_cert_get_issuer(tsl_csr_fields_t *issuer)
{
  if (issuer == NULL) return -1;

  copy_to_fields(X509_NAME_oneline(X509_get_issuer_name(loadedCert), NULL, 0), issuer);

  return 0;
}

int tsl_cert_get_subject(tsl_csr_fields_t *subject)
{
  if (subject == NULL) return -1;

  copy_to_fields(X509_NAME_oneline(X509_get_subject_name(loadedCert), NULL, 0), subject);

  return 0;
}

int tsl_cert_check_date_valid()
{
  int ret = 0;
  time_t *ptime = NULL;

  ret = X509_cmp_time(X509_get_notBefore(loadedCert), ptime);
  ret &= X509_cmp_time(X509_get_notAfter(loadedCert), ptime);

  if (ret == -1) ret = 0;
  else if (ret == 0) ret = -1; // -1 is error

  return ret;
}

int tsl_release_keys()
{
  return 0;
}

int tsl_sign(void *data, size_t dlen, void *ciphertext, size_t *clen)
{
  EVP_MD_CTX *mdctx = NULL;
  int ret = -1;
  INIT_ERROR_CHECK();
  
  ERROR_CHECK(mdctx = EVP_MD_CTX_create(), { return -1; });
  ERROR_CHECK(EVP_DigestSignInit(mdctx, NULL, SIGN_TYPE, NULL, loadedPrivKey), { goto tsl_sign_ret; });
  ERROR_CHECK(EVP_DigestSignUpdate(mdctx, data, dlen), { goto tsl_sign_ret; });
  
  ERROR_CHECK(EVP_DigestSignFinal(mdctx, ciphertext, clen), { goto tsl_sign_ret; });

  ret = 0;
tsl_sign_ret:
  EVP_MD_CTX_destroy(mdctx);
  return ret;
}

int tsl_verify(void *ciphertext, size_t clen, void *data, size_t dlen)
{
  EVP_MD_CTX *mdctx;
  int ret = -1;
  INIT_ERROR_CHECK();

  if (clen == -1) clen = strlen((const char*)ciphertext);
  if (dlen == -1) dlen = strlen((const char*)data);

  ERROR_CHECK(mdctx = EVP_MD_CTX_create(), { return -1; });

  ERROR_CHECK(EVP_DigestVerifyInit(mdctx, NULL, SIGN_TYPE, NULL, loadedPublKey), { goto tsl_verify_ret; });
  ERROR_CHECK(EVP_DigestVerifyUpdate(mdctx, data, dlen), { goto tsl_verify_ret; });

  ret = EVP_DigestVerifyFinal(mdctx, ciphertext, clen);
tsl_verify_ret:
  EVP_MD_CTX_destroy(mdctx);
  // free(signedData);

  return ret;
}

static void setFields(X509_NAME *name, tsl_csr_fields_t *fields)
{
  if (fields->country[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "C" , MBSTRING_ASC, (const unsigned char*)fields->country, -1, -1, 0);
  if (fields->state[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)fields->state, -1, -1, 0);
  if (fields->locality[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "L" , MBSTRING_ASC, (const unsigned char*)fields->locality, -1, -1, 0);
  if (fields->commonName[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)fields->commonName, -1, -1, 0);
  if (fields->org[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "O" , MBSTRING_ASC, (const unsigned char*)fields->org, -1, -1, 0);
  if (fields->unit[0] != '\0')
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)fields->unit, -1, -1, 0);
}

int tsl_create_self_signed_cert(char *certFile, long daysValid, tsl_csr_fields_t fields)
{
  FILE *certFile_fp;
  X509 *cert;
  X509_NAME *name;
  INIT_ERROR_CHECK();

  if ((certFile_fp = fopen(certFile, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }

  ERROR_CHECK(cert = X509_new(), { return -1; });
    
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), daysValid * 24 * 60 * 60);
  
  name = X509_get_subject_name(cert);
  
  setFields(name, &fields);

  /* self signed cert issuer == subject */
  X509_set_subject_name(cert, name);
  X509_set_issuer_name(cert, name);
  // TODO: set isCA:TRUE flag

  X509_set_pubkey(cert, (EVP_PKEY*)loadedPrivKey);
  
  /* Actually sign the certificate with our key. */
  ERROR_CHECK(X509_sign(cert, (EVP_PKEY*)loadedPrivKey, SIGN_TYPE), { return -1; });

  if ((certFile_fp = fopen(certFile, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(PEM_write_X509(certFile_fp, cert), { return -1; });

  fclose(certFile_fp);
  X509_free(cert);

  return 0;
}

int tsl_cert(char *certFile, char *csrFile, long daysValid, tsl_csr_fields_t issuerFields)
{
  FILE *csr_fp, *crt_fp;
  X509_REQ *csr;
  X509 *crt;
  X509_NAME *subject;
  X509_NAME *issuer;
  INIT_ERROR_CHECK();

  if ((csr_fp = fopen(csrFile, "rb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(csr = PEM_read_X509_REQ(csr_fp, NULL, NULL, NULL), { return -1; });
  ERROR_CHECK(crt = X509_new(), { return -1; });
  ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
  
  X509_gmtime_adj(X509_get_notBefore(crt), 0);
  X509_gmtime_adj(X509_get_notAfter(crt), daysValid * 24 * 60 * 60);

  subject = X509_REQ_get_subject_name(csr);
  issuer = X509_get_issuer_name(crt);
  
  setFields(issuer, &issuerFields);

  /* self signed cert issuer == subject */
  X509_set_subject_name(crt, subject);
  X509_set_issuer_name(crt, issuer);

  if (loadedPublKey != NULL) {
    EVP_PKEY_free(loadedPublKey);
  }
  loadedPublKey = X509_REQ_get_pubkey(csr);
  X509_set_pubkey(crt, loadedPublKey);
  ERROR_CHECK(X509_sign(crt, loadedPrivKey, SIGN_TYPE), { return -1; });

  if ((crt_fp = fopen(certFile, "wb")) == NULL) {
    TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
    return -1;
  }
  ERROR_CHECK(PEM_write_X509(crt_fp, crt), { return -1; });

  fclose(csr_fp);
  fclose(crt_fp);

  X509_REQ_free(csr);
  X509_free(crt);

  return 0;
}

int tsl_get_ec_key(void **eckey)
{
  INIT_ERROR_CHECK();
  ERROR_CHECK((*eckey = (void*)EVP_PKEY_get1_EC_KEY(loadedPrivKey)), { return -1; });
  return 0;
}

int tsl_get_ec_from_pubkey(void **eckey)
{
  INIT_ERROR_CHECK();
  ERROR_CHECK((*eckey = (void*)EVP_PKEY_get1_EC_KEY(loadedPublKey)), { return -1; });
  return 0;
}

int tsl_serialize_ec_pubkey(void *eckey, void *buffer, size_t size)
{
  BIO *bo = NULL;
  EC_KEY *key = (EC_KEY*)eckey;
  int ret = -1;
  char *data;
  long dataLen;
  INIT_ERROR_CHECK();

  bo = BIO_new(BIO_s_mem());
  // bo = BIO_new_mem_buf(buffer, size);
  // ERROR_CHECK(BIO_set_mem_buf(bo, ret, BIO_NOCLOSE), { ret = (void*)-1; goto ret; });

  ERROR_CHECK(PEM_write_bio_EC_PUBKEY(bo, key), { goto ret; });

  dataLen = BIO_get_mem_data(bo, &data);
  if (dataLen > size) {
    TSL_ADD_ERROR("[ERROR]: not enough space on buffer (requires %li bytes but only %zu provided)\n", dataLen, size);
    goto ret;
  }
  memcpy(buffer, data, dataLen);

ret:
  BIO_free_all(bo);
  return ret;
}

int tsl_deserialize_ec_pubkey(void *buffer, size_t size, void **eckey)
{
  BIO *bo = NULL;
  int ret = -1;
  INIT_ERROR_CHECK();

  bo = BIO_new(BIO_s_mem());
  BIO_write(bo, buffer, size);
  ERROR_CHECK(*((EC_KEY**)eckey) = PEM_read_bio_EC_PUBKEY(bo, NULL, NULL, NULL), { goto ret; });

  ret = 0;
ret:
  BIO_free_all(bo);
  return ret;
}

int tsl_create_secret(void *peerkey)
{
  EC_KEY *peer_eckey = (EC_KEY*)peerkey;
  EC_KEY *local_eckey;
  const EC_POINT *public = EC_KEY_get0_public_key(peer_eckey);
	unsigned char *secret;
  size_t secret_size;
  int ret = -1;
  INIT_ERROR_CHECK();

  ERROR_CHECK((local_eckey = (void*)EVP_PKEY_get1_EC_KEY(loadedPrivKey)), { goto ret; });

	secret_size = GET_SECRET_LEN(local_eckey);

	ERROR_CHECK((secret = OPENSSL_malloc(secret_size)), { goto ret; });
	ERROR_CHECK((secret_size = ECDH_compute_key(secret, secret_size, public, local_eckey, NULL)),
    { goto ret1; });

  if (negotiatedKeys[negotiatedKeysSize] != NULL) {
    OPENSSL_free(negotiatedKeys[negotiatedKeysSize]);
  }
	ERROR_CHECK((negotiatedKeys[negotiatedKeysSize] = OPENSSL_malloc(HASH_SIZE)), { goto ret1; });
  tsl_hash(secret, secret_size, negotiatedKeys[negotiatedKeysSize], NULL);
  negotiatedKeysSize++;

  ret = negotiatedKeysSize - 1;

ret1:
  OPENSSL_free(secret);
ret:
	return ret;
}

int tsl_clear_all_secrets()
{
  for (int i = 0; i < negotiatedKeysSize; ++i) {
    OPENSSL_free(negotiatedKeys[i]);
  }
  negotiatedKeysSize = 0;
  return 0;
}

int tsl_load_secret(int keyid)
{
  memcpy(loadedSimKey, negotiatedKeys[keyid], HASH_SIZE);
  tsl_hash(loadedSimKey, HASH_SIZE, loadedIV, NULL);
  return 0;
}

int tsl_sym_load_key(char *symkey)
{
  tsl_hash(symkey, strlen(symkey), loadedSimKey, NULL);
  tsl_hash(loadedSimKey, HASH_SIZE, loadedIV, NULL);
  return 0;
}

int tsl_sym_cipher(void *data, size_t dlen, void *ciphertext, size_t *clen)
{
  EVP_CIPHER_CTX *ctx;
  int ret = -1;
  int len, len2;
  INIT_ERROR_CHECK();

  ERROR_CHECK((ctx = EVP_CIPHER_CTX_new()), { goto ret; });
  ERROR_CHECK(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, loadedSimKey, loadedIV), { goto ret; });
  ERROR_CHECK(EVP_EncryptUpdate(ctx, ciphertext, &len, data, dlen), { goto ret; });
  ERROR_CHECK(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len2), { goto ret; });
  *clen = len + len2;
  ret = 0;
ret:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int tsl_sym_decipher(void *ciphertext, size_t clen, void *data, size_t *dlen)
{
  EVP_CIPHER_CTX *ctx;
  int ret = -1;
  int len, len2;
  INIT_ERROR_CHECK();

  ERROR_CHECK((ctx = EVP_CIPHER_CTX_new()), { goto ret; });
  ERROR_CHECK(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, loadedSimKey, loadedIV), { goto ret; });
  ERROR_CHECK(EVP_DecryptUpdate(ctx, data, &len, ciphertext, clen), { goto ret; });
  ERROR_CHECK(EVP_DecryptFinal_ex(ctx, data + len, &len2), { goto ret; });
  *dlen = len + len2;
  ret = 0;
ret:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int tsl_hash(void *data, size_t dlen, void *hashed, size_t *hlen)
{
  if (hlen != NULL) {
    *hlen = SHA512_DIGEST_LENGTH;
  }
  if (data == NULL || hashed == NULL) {
    return SHA512_DIGEST_LENGTH;
  }
  SHA512_CTX sha512;
  SHA512_Init(&sha512);
  SHA512_Update(&sha512, data, dlen);
  SHA512_Final(hashed, &sha512);
  return 0;
}

int tsl_hmac(void *data, size_t dlen, void *out, size_t *olen)
{
  unsigned int hmac_len;
  HMAC(HASH_TYPE, loadedSimKey, HASH_SIZE, data, dlen, out, &hmac_len);
  *olen = (size_t)hmac_len;
  return 0;
}

static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char reverse_table[128] = {
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
   64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
   64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

int tsl_base64_encode(char *data, size_t dlen, char *out, size_t *olen)
{
  // Use = signs so the end is properly padded.
  size_t outpos = 0;
  size_t len = 0;
  int bits_collected = 0;
  unsigned int accumulator = 0;

  len = ((dlen + 2) / 3) * 4;
  memset(out, '=', len);
  out[len] = '\0';

  for (int i = 0; i < dlen; ++i) {
    accumulator = (accumulator << 8) | (data[i] & 0xffu); // char == 8 bits
    bits_collected += 8;
    while (bits_collected >= 6) {
      bits_collected -= 6;
      out[outpos++] = b64_table[(accumulator >> bits_collected) & 0x3fu];
    }
  }
  if (bits_collected > 0) { // Any trailing bits that are missing.
    accumulator <<= 6 - bits_collected;
    out[outpos++] = b64_table[accumulator & 0x3fu];
  }
  *olen = len;
  return 0;
}

int tsl_base64_decode(char *data, size_t dlen, char *out, size_t *olen)
{
  int bits_collected = 0;
  unsigned int accumulator = 0;
  size_t len = 0;
  
  for (int i = 0; i < dlen; ++i) {
    const int c = data[i];
    if (isspace(c) || c == '=') {
      // Skip whitespace and padding. Be liberal in what you accept.
      continue;
    }
    if ((c > 127) || (c < 0) || (reverse_table[c] > 63)) {
      return -1;
    }
    accumulator = (accumulator << 6) | reverse_table[c];
    bits_collected += 6;
    if (bits_collected >= 8) {
      bits_collected -= 8;
      out[len++] = (accumulator >> bits_collected) & 0xffu;
    }
  }
  *olen = len;
  return 0;
}
