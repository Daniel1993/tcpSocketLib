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

// static EVP_PKEY *loadedPrivKey = NULL;
// static X509 *loadedCert = NULL;
// static EVP_PKEY *loadedPublKey = NULL; // this should be a x509 cert
// static unsigned char loadedSimKey[HASH_SIZE];
// static unsigned char loadedIV[HASH_SIZE];

#define GET_SECRET_LEN(_eckey) \
  ((EC_GROUP_get_degree(EC_KEY_get0_group(_eckey)) + 7) / 8) \
// ECDH_size(_eckey)
//

struct tsl_identity_t {
  EVP_PKEY *privKey;
  EVP_PKEY *publKey;
  X509_REQ *csr;
  X509 *ca;
  X509 *cert;
  unsigned char *secret;
  unsigned char *ecc_secret;
  unsigned char *secretIV;
  unsigned char *ecc_secretIV;
  EVP_PKEY *ecc_gen_key;
  EVP_PKEY *ecc_gen_key_pub;
  EC_KEY *ecc_gen_key1;
  EC_KEY *ecc_dec_key1;
};

// static void *negotiatedKeys[TSL_MAX_SECRETS];
// static size_t negotiatedKeysSize = 0;

static void copy_to_fields(char *str, tsl_csr_fields_t *fields);
static void setFields(X509_NAME *name, tsl_csr_fields_t *fields);

tsl_identity_t *tsl_alloc_identity()
{
  tsl_identity_t *res = (tsl_identity_t*)malloc(sizeof(tsl_identity_t));
  memset(res, 0, sizeof(tsl_identity_t));
  return res;
}

void tsl_free_identity(tsl_identity_t *identity)
{
  tsl_id_destroy_keys(identity);
  free(identity);
}


int tsl_id_destroy_keys(tsl_identity_t *identity)
{
  if (identity->privKey)   EVP_PKEY_free(identity->privKey);
  if (identity->publKey)   EVP_PKEY_free(identity->publKey);
  if (identity->csr)       X509_REQ_free(identity->csr);
  if (identity->ca)        X509_free(identity->ca);
  if (identity->cert)      X509_free(identity->cert);
  if (identity->ecc_secret)   OPENSSL_free(identity->ecc_secret);
  if (identity->ecc_secretIV) OPENSSL_free(identity->ecc_secretIV);
  if (identity->secret)       OPENSSL_free(identity->secret);
  if (identity->secretIV)     OPENSSL_free(identity->secretIV);
  if (identity->ecc_gen_key)     EVP_PKEY_free(identity->ecc_gen_key);
  if (identity->ecc_gen_key_pub) EVP_PKEY_free(identity->ecc_gen_key_pub);
  if (identity->ecc_gen_key1)    EC_KEY_free(identity->ecc_gen_key1);
  if (identity->ecc_dec_key1)    EC_KEY_free(identity->ecc_dec_key1);
  return 0;
}

// TODO: add passphrase to private key
int tsl_store_identity(
  tsl_identity_t *identity,
  const char *priv_key,
  const char *publ_key,
  const char *cert_req,
  const char *cert,
  const char *ca
) {
  FILE *priv_key_fp, *publ_key_fp, *cert_req_fp, *cert_fp, *ca_fp;
  INIT_ERROR_CHECK();

  if (identity->privKey && priv_key) {
    if ((priv_key_fp = fopen(priv_key, "wb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(PEM_write_PrivateKey(priv_key_fp, identity->privKey, NULL, NULL, 0, 0, NULL),
      { fclose(priv_key_fp); return -1; });
    fclose(priv_key_fp);
  }
  
  if (identity->publKey && publ_key) {
    if ((publ_key_fp = fopen(publ_key, "wb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }

    ERROR_CHECK(PEM_write_PUBKEY(publ_key_fp, identity->publKey), 
      { fclose(publ_key_fp); return -1; });
    fclose(publ_key_fp);
  }

  if (identity->csr && cert_req) {
    if ((cert_req_fp = fopen(cert_req, "wb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(PEM_write_X509_REQ_NEW(cert_req_fp, identity->csr),
      { fclose(cert_req_fp); return -1; });
    fclose(cert_req_fp);
  }

  if (identity->cert && cert) {
    if ((cert_fp = fopen(cert, "wb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(PEM_write_X509(cert_fp, identity->cert),
      { fclose(cert_fp); return -1; });
    fclose(cert_fp);
  }

  if (identity->ca && ca) {
    if ((ca_fp = fopen(ca, "wb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(PEM_write_X509(ca_fp, identity->ca),
      { fclose(ca_fp); return -1; });
    fclose(ca_fp);
  }

  return 0;
}

int tsl_load_identity(
  tsl_identity_t *identity,
  const char *priv_key,
  const char *publ_key,
  const char *cert_req,
  const char *cert,
  const char *ca
) {
  FILE *priv_key_fp, *publ_key_fp, *cert_req_fp, *cert_fp, *ca_fp;
  INIT_ERROR_CHECK();

  if (priv_key) {
    if ((priv_key_fp = fopen(priv_key, "rb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    // TODO: passphrase
    ERROR_CHECK((identity->privKey = PEM_read_PrivateKey(priv_key_fp, NULL, NULL, NULL)),
      { fclose(priv_key_fp); return -1; });
    fclose(priv_key_fp);
  }
  
  if (publ_key) {
    if ((publ_key_fp = fopen(publ_key, "rb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }

    ERROR_CHECK(identity->publKey = PEM_read_PUBKEY(publ_key_fp, NULL, NULL, NULL), 
      { fclose(publ_key_fp); return -1; });
    fclose(publ_key_fp);
  }

  if (cert_req) {
    if ((cert_req_fp = fopen(cert_req, "rb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(identity->csr = PEM_read_X509_REQ(cert_req_fp, NULL, NULL, NULL),
      { fclose(cert_req_fp); return -1; });
    fclose(cert_req_fp);
  }

  if (cert) {
    if ((cert_fp = fopen(cert, "rb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(identity->cert = PEM_read_X509(cert_fp, NULL, NULL, NULL),
      { fclose(cert_fp); return -1; });
    fclose(cert_fp);
  }

  if (ca) {
    if ((ca_fp = fopen(ca, "rb")) == NULL) {
      TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno));
      return -1;
    }
    ERROR_CHECK(identity->ca = PEM_read_X509(ca_fp, NULL, NULL, NULL),
      { fclose(ca_fp); return -1; });
    fclose(ca_fp);
  }

  return 0;
}

int tsl_id_create_keys(tsl_identity_t *identity, tsl_csr_fields_t fields)
{
  int res = -1;
  EC_KEY *ecc;
  X509_REQ *x509_req;
  X509_NAME *x509_name;
  INIT_ERROR_CHECK();

  ecc = EC_KEY_new_by_curve_name(ECC_CURVE);
  EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

  ERROR_CHECK(EC_KEY_generate_key(ecc), { goto ret; });
  identity->privKey = EVP_PKEY_new();
  ERROR_CHECK(EVP_PKEY_assign_EC_KEY(identity->privKey, ecc),
    { EVP_PKEY_free(identity->privKey); goto ret; });
  
  identity->publKey = EVP_PKEY_new();
  ERROR_CHECK(EVP_PKEY_assign_EC_KEY(identity->publKey, 
    EVP_PKEY_get1_EC_KEY(identity->privKey)),
    { EVP_PKEY_free(identity->privKey); EVP_PKEY_free(identity->publKey); goto ret; });

  x509_req = X509_REQ_new();
  ERROR_CHECK(X509_REQ_set_version(x509_req, 1 /* version */), {
    X509_REQ_free(x509_req); EVP_PKEY_free(identity->privKey); EVP_PKEY_free(identity->publKey);
    goto ret; });
  x509_name = X509_REQ_get_subject_name(x509_req);
  X509_NAME_add_entry_by_txt(x509_name, "C" , MBSTRING_ASC, (const unsigned char*)fields.country, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, (const unsigned char*)fields.state, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "L" , MBSTRING_ASC, (const unsigned char*)fields.locality, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char*)fields.commonName, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "O" , MBSTRING_ASC, (const unsigned char*)fields.org, -1, -1, 0);
  X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, (const unsigned char*)fields.unit, -1, -1, 0);

  ERROR_CHECK(X509_REQ_set_pubkey(x509_req, identity->privKey), { 
    X509_REQ_free(x509_req); EVP_PKEY_free(identity->privKey); EVP_PKEY_free(identity->publKey); 
    goto ret; });
  ERROR_CHECK(X509_REQ_sign(x509_req, identity->privKey, SIGN_TYPE), {
    X509_REQ_free(x509_req); EVP_PKEY_free(identity->privKey); EVP_PKEY_free(identity->publKey);
    goto ret; });
  identity->csr = x509_req;

  res = 0;
ret:
  EC_KEY_free(ecc);
  return res;
}

int tsl_id_cert_get_issuer(tsl_identity_t *identity, tsl_csr_fields_t *issuer)
{
  if (issuer == NULL) return -1;
  copy_to_fields(X509_NAME_oneline(X509_get_issuer_name(identity->cert), NULL, 0), issuer);
  return 0;
}

int tsl_id_cert_get_subject(tsl_identity_t *identity, tsl_csr_fields_t *subject)
{
  if (subject == NULL) return -1;
  copy_to_fields(X509_NAME_oneline(X509_get_subject_name(identity->cert), NULL, 0), subject);
  return 0;
}

int tsl_id_cert_check_date_valid(tsl_identity_t *identity)
{
  int ret = 0;
  time_t *ptime = NULL;

  ret = X509_cmp_time(X509_get_notBefore(identity->cert), ptime);
  ret &= X509_cmp_time(X509_get_notAfter(identity->cert), ptime);

  if (ret == -1) ret = 0;
  else if (ret == 0) ret = -1; // -1 is error

  return ret;
}

int tsl_id_create_self_signed_cert(tsl_identity_t *identity, long daysValid, tsl_csr_fields_t fields)
{
  X509_NAME *name;
  INIT_ERROR_CHECK();

  ERROR_CHECK(identity->cert = X509_new(), { return -1; });
    
  ASN1_INTEGER_set(X509_get_serialNumber(identity->cert), 1);
  
  X509_gmtime_adj(X509_get_notBefore(identity->cert), 0);
  X509_gmtime_adj(X509_get_notAfter(identity->cert), daysValid * 24 * 60 * 60);
  
  name = X509_get_subject_name(identity->cert);
  
  setFields(name, &fields);

  /* self signed cert issuer == subject */
  X509_set_subject_name(identity->cert, name);
  X509_set_issuer_name(identity->cert, name);
  // TODO: set isCA:TRUE flag

  X509_set_pubkey(identity->cert, identity->privKey);
  
  /* Actually sign the certificate with our key. */
  ERROR_CHECK(X509_sign(identity->cert, identity->privKey, SIGN_TYPE), { return -1; });
  return 0;
}

int tsl_id_cert(tsl_identity_t *ca, tsl_identity_t *csr, long daysValid, tsl_csr_fields_t issuerFields)
{
  X509_NAME *subject;
  X509_NAME *issuer;
  EVP_PKEY *pkey;
  INIT_ERROR_CHECK();

  ERROR_CHECK(csr->cert = X509_new(), { return -1; });
  ASN1_INTEGER_set(X509_get_serialNumber(csr->cert), 1);
  
  X509_gmtime_adj(X509_get_notBefore(csr->cert), 0);
  X509_gmtime_adj(X509_get_notAfter(csr->cert), daysValid * 24 * 60 * 60);

  subject = X509_REQ_get_subject_name(csr->csr);
  issuer = X509_get_issuer_name(csr->cert);
  
  setFields(issuer, &issuerFields);

  /* self signed cert issuer == subject */
  X509_set_subject_name(csr->cert, subject);
  X509_set_issuer_name(csr->cert, issuer);

  pkey = X509_REQ_get_pubkey(csr->csr);
  X509_set_pubkey(csr->cert, pkey);
  ERROR_CHECK(X509_sign(csr->cert, ca->privKey, SIGN_TYPE), { return -1; });

  return 0;
}

int tsl_id_sign(tsl_identity_t *id, void *data, size_t dlen, void *ciphertext, size_t *clen)
{
  EVP_MD_CTX *mdctx = NULL;
  int ret = -1;
  INIT_ERROR_CHECK();
  
  if (dlen == -1) dlen = strlen((const char*)data);

  ERROR_CHECK(mdctx = EVP_MD_CTX_create(), { return -1; });
  ERROR_CHECK(EVP_DigestSignInit(mdctx, NULL, SIGN_TYPE, NULL, id->privKey), { goto tsl_sign_ret; });
  ERROR_CHECK(EVP_DigestSignUpdate(mdctx, data, dlen), { goto tsl_sign_ret; });
  
  ERROR_CHECK(EVP_DigestSignFinal(mdctx, ciphertext, clen), { goto tsl_sign_ret; });

  ret = 0;
tsl_sign_ret:
  EVP_MD_CTX_destroy(mdctx);
  return ret;
}

int tsl_id_verify(tsl_identity_t *id, void *ciphertext, size_t clen, void *data, size_t dlen)
{
  EVP_MD_CTX *mdctx;
  int ret = -1;
  INIT_ERROR_CHECK();

  if (clen == -1) clen = strlen((const char*)ciphertext);
  if (dlen == -1) dlen = strlen((const char*)data);

  ERROR_CHECK(mdctx = EVP_MD_CTX_create(), { return -1; });

  ERROR_CHECK(EVP_DigestVerifyInit(mdctx, NULL, SIGN_TYPE, NULL, id->publKey), { goto tsl_verify_ret; });
  ERROR_CHECK(EVP_DigestVerifyUpdate(mdctx, data, dlen), { goto tsl_verify_ret; });

  ret = EVP_DigestVerifyFinal(mdctx, ciphertext, clen);
tsl_verify_ret:
  EVP_MD_CTX_destroy(mdctx);
  return ret;
}

int tsl_id_cert_verify(tsl_identity_t *cert, tsl_identity_t *issuer, const char **err_str)
{
  int ret = -1;
  INIT_ERROR_CHECK();

  X509_STORE* store = X509_STORE_new();
  ERROR_CHECK(store, { return -1; });
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  ERROR_CHECK(ctx, { goto ret_store; });

  static const long flags = X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_POLICY_CHECK;
  int rc = X509_STORE_set_flags(store, flags);
  ERROR_CHECK(rc, { goto ret_store_ctx; });

  ERROR_CHECK(X509_STORE_add_cert(store, issuer->cert), { goto ret_store_ctx; });

  rc = X509_STORE_CTX_init(ctx, store, cert->cert, NULL);
  ERROR_CHECK(rc, { goto ret_store_ctx; });
  
  ret = X509_verify_cert(ctx);
  int err = X509_STORE_CTX_get_error(ctx);
  if (err_str != NULL && err != 0) {
    *err_str = X509_verify_cert_error_string(err);
  }

ret_store_ctx:
  X509_STORE_CTX_free(ctx);
ret_store:
  X509_STORE_free(store);
  return ret;
}

int tsl_id_gen_ec_key(tsl_identity_t *id)
{
  tsl_identity_t *new_key;
  int res = -1;
  INIT_ERROR_CHECK();

  new_key = tsl_alloc_identity();
  tsl_id_create_keys(new_key, (tsl_csr_fields_t){});
  if (new_key->csr) {
    X509_REQ_free(new_key->csr);
  }
  if (new_key->ca) {
    X509_free(new_key->ca);
  }
  if (new_key->cert) {
    X509_free(new_key->cert);
  }
  id->ecc_gen_key = new_key->privKey;
  id->ecc_gen_key_pub = new_key->publKey;

  ERROR_CHECK((id->ecc_gen_key1 = EVP_PKEY_get1_EC_KEY(id->ecc_gen_key_pub)), { goto ret; });

  res = 0;
ret:
  free(new_key);
  return res;
}

int tsl_id_serialize_ec_pubkey(tsl_identity_t *id, void *buffer, size_t size)
{
  BIO *bo = NULL;
  EC_KEY *key = id->ecc_gen_key1;
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

int tsl_id_deserialize_ec_pubkey(tsl_identity_t *id, void *buffer, size_t size)
{
  BIO *bo = NULL;
  int ret = -1;
  INIT_ERROR_CHECK();

  bo = BIO_new(BIO_s_mem());
  BIO_write(bo, buffer, size);
  ERROR_CHECK(id->ecc_dec_key1 = PEM_read_bio_EC_PUBKEY(bo, NULL, NULL, NULL), { goto ret; });

  ret = 0;
ret:
  BIO_free_all(bo);
  return ret;
}

int tsl_id_gen_peer_secret(tsl_identity_t *id, tsl_identity_t *peer)
{
  if (id->ecc_gen_key1 == NULL) {
    TSL_ADD_ERROR("[ERROR]: call first tsl_id_serialize_ec_pubkey on id\n");
    return -1;
  }
  if (peer->ecc_dec_key1 == NULL) {
    TSL_ADD_ERROR("[ERROR]: call first tsl_id_deserialize_ec_pubkey on peer\n");
    return -1;
  }
  EC_KEY *peer_eckey = (EC_KEY*)peer->ecc_dec_key1;
  // EC_KEY *peer_eckey = (EC_KEY*) EVP_PKEY_get0_EC_KEY(peer->publKey);
  EC_KEY *local_eckey;
  const EC_POINT *public = EC_KEY_get0_public_key(peer_eckey);
  unsigned char *secret;
  size_t secret_size;
  int ret = -1;
  INIT_ERROR_CHECK();

  ERROR_CHECK((local_eckey = id->ecc_gen_key1), { goto ret; });
  // ERROR_CHECK((local_eckey = (void*)EVP_PKEY_get1_EC_KEY(id->privKey)), { goto ret; });

  secret_size = GET_SECRET_LEN(local_eckey);

  ERROR_CHECK((secret = OPENSSL_malloc(secret_size)), { goto ret; });
  ERROR_CHECK((secret_size = ECDH_compute_key(secret, secret_size, public, local_eckey, NULL)),
    { goto ret1; });

  if (peer->ecc_secret != NULL) {
    OPENSSL_free(peer->ecc_secret);
  }
  ERROR_CHECK((peer->ecc_secret = OPENSSL_malloc(HASH_SIZE)), { goto ret1; });
  tsl_hash(secret, secret_size, peer->ecc_secret, NULL);
  if (peer->ecc_secretIV != NULL) {
    OPENSSL_free(peer->ecc_secretIV);
  }
  ERROR_CHECK((peer->ecc_secretIV = OPENSSL_malloc(HASH_SIZE)), { goto ret1; });
  tsl_hash(peer->ecc_secret, HASH_SIZE, peer->ecc_secretIV, NULL);

  ret = 0;
ret1:
  OPENSSL_free(secret);
ret:
  return ret;
}

int tsl_id_load_secret(tsl_identity_t *id, char *secret)
{
  if (id->secret != NULL) {
    OPENSSL_free(id->secret);
  }
  if (id->secretIV != NULL) {
    OPENSSL_free(id->secretIV);
  }
  id->secret = OPENSSL_malloc(HASH_SIZE);
  id->secretIV = OPENSSL_malloc(HASH_SIZE);
  if (!secret) {
    if (!id->ecc_secret) {
      TSL_ADD_ERROR("[ERROR]: call tsl_id_gen_peer_secret first to generate the secret\n");
      return -1;
    }
    memcpy(id->secret, id->ecc_secret, HASH_SIZE);
    memcpy(id->secretIV, id->ecc_secretIV, HASH_SIZE);
  } else {
    memcpy(id->secret, secret, HASH_SIZE);
    tsl_hash(id->secret, HASH_SIZE, id->secretIV, NULL);
  }
  return 0;
}

int tsl_id_sym_cipher(tsl_identity_t *id, void *data, size_t dlen, void *ciphertext, size_t *clen)
{
  EVP_CIPHER_CTX *ctx;
  int ret = -1;
  int len, len2;
  INIT_ERROR_CHECK();

  ERROR_CHECK((ctx = EVP_CIPHER_CTX_new()), { goto ret; });
  ERROR_CHECK(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, id->secret, id->secretIV), { goto ret; });
  ERROR_CHECK(EVP_EncryptUpdate(ctx, ciphertext, &len, data, dlen), { goto ret; });
  ERROR_CHECK(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len2), { goto ret; });
  *clen = len + len2;
  ret = 0;
ret:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int tsl_id_sym_decipher(tsl_identity_t *id, void *ciphertext, size_t clen, void *data, size_t *dlen)
{
  EVP_CIPHER_CTX *ctx;
  int ret = -1;
  int len, len2;
  INIT_ERROR_CHECK();

  ERROR_CHECK((ctx = EVP_CIPHER_CTX_new()), { goto ret; });
  ERROR_CHECK(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, id->secret, id->secretIV), { goto ret; });
  ERROR_CHECK(EVP_DecryptUpdate(ctx, data, &len, ciphertext, clen), { goto ret; });
  ERROR_CHECK(EVP_DecryptFinal_ex(ctx, data + len, &len2), { goto ret; });
  *dlen = len + len2;
  ret = 0;
ret:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
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

int tsl_id_hmac(tsl_identity_t *id, void *data, size_t dlen, void *out, size_t *olen)
{
  unsigned int hmac_len;
  HMAC(HASH_TYPE, id->secret, HASH_SIZE, data, dlen, out, &hmac_len);
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
  if (olen) *olen = len;
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
