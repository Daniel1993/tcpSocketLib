#ifndef TCP_SOCKET_LIB_GUARD_
#define TCP_SOCKET_LIB_GUARD_

#define TSL_MAX_HANDLERS        64
#define TSL_HASH_SIZE           64 /* SHA512 */
#define TSL_SIGNATURE_SIZE    1024 /* TODO */
#define TSL_MAX_CONNECTIONS   1024
#define TSL_MSG_QUEUE_SIZE      16
#define TSL_HANDLER_THREADS      8
#define TSL_MSG_BUFFER      262144 /* 256kB */
#define TSL_MAX_SECRETS       1024
#define TSL_CSR_FIELD_SIZE     128

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "handleError.h"

typedef struct tsl_csr_fields_t {
  char country   [TSL_CSR_FIELD_SIZE];
  char state     [TSL_CSR_FIELD_SIZE];
  char locality  [TSL_CSR_FIELD_SIZE];
  char org       [TSL_CSR_FIELD_SIZE];
  char unit      [TSL_CSR_FIELD_SIZE];
  char commonName[TSL_CSR_FIELD_SIZE];
  char email     [TSL_CSR_FIELD_SIZE];
} tsl_csr_fields_t;

typedef struct tsl_identity_t tsl_identity_t;

typedef void(*tsl_handler_t)(void*,size_t,void(*respondWith)(void*,size_t),void(*waitResponse)(void*, size_t*)); 

// if isServerSet returns -2 server is already running
int tsl_init(char *port); // port == NULL --> any port
int tsl_check_port(); // returns the port the server is bind to
int tsl_destroy();

/**
 * Connects to <address>:<port>
 * returns:  0 // no error
 *          -1 // max number of connections reached
 *          -2 // error address format
 *          -3 // error openning socket or connecting
 **/
int tsl_connect_to(char *addr, char *port); // prints connection count

int tsl_close_all_connections(); // closes all connections
int tsl_send_msg(int connId, void *msg, size_t);
int tsl_recv_msg(int connId, void *msg, size_t*);

// NOTE: handlers are executed sequentially
int tsl_add_handler(tsl_handler_t);

tsl_identity_t *tsl_alloc_identity();
void tsl_free_identity(tsl_identity_t *identity);

// return -1 for error
int tsl_store_identity(
  tsl_identity_t *identity,
  const char *priv_key,
  const char *publ_key,
  const char *cert_req,
  const char *cert,
  const char *ca
);

// return -1 for error, 0 no error,
// 1 could not open priv (can be in any bit combination)
// 2 could not open publ
// 4 could not open csr
// 8 could not open cert
// 16 could not open ca
int tsl_load_identity(
  tsl_identity_t *identity,
  const char *priv_key,
  const char *publ_key,
  const char *cert_req,
  const char *cert,
  const char *ca
);
int tsl_id_create_keys(
  tsl_identity_t *identity,
  int secStrength /* 1 - weakest, 3 - strongest */,
  tsl_csr_fields_t fields
);
int tsl_id_destroy_keys(tsl_identity_t *identity);
int tsl_id_cert_get_issuer(tsl_identity_t*, tsl_csr_fields_t*); // load first
int tsl_id_cert_get_subject(tsl_identity_t*, tsl_csr_fields_t*); // load first
int tsl_id_cert_check_date_valid(tsl_identity_t*); // load first, returns 1 on valid, 0 not valid, -1 error
int tsl_id_create_self_signed_cert(tsl_identity_t*, long daysValid, tsl_csr_fields_t subject);
int tsl_id_cert(tsl_identity_t *ca, tsl_identity_t *csr, long daysValid, tsl_csr_fields_t issuer);
int tsl_id_cert_verify(tsl_identity_t *cert, tsl_identity_t *issuer, const char **err_str);

// NOTE: programmer must give enough space in buffers, this will not malloc!
// ciphers with private key (consider using a hash)
int tsl_id_sign(
  tsl_identity_t*,
  void *data,       size_t dlen,
  void *ciphertext, size_t *clen
); // clen --> must containt the size of the buffer

// checks with public key
int tsl_id_verify(
  tsl_identity_t*,
  void *ciphertext, size_t clen,
  void *data,       size_t dlen
); // -1 is an error, 1 is ok, 0 is false

// secret sharing methods

// generates ephemeral key
int tsl_id_gen_ec_key(tsl_identity_t *id);
// serializes the ephemeral (public) key, after this, send the buffer to the peer, returns space taken
long tsl_id_serialize_ec_pubkey(tsl_identity_t *id, void *buffer, size_t size);
// deserialize ephemeral key from peer
int tsl_id_deserialize_ec_pubkey(tsl_identity_t *peer, void *buffer, size_t size); // pass &eckey, where eckey is void* = NULL
// after generated and received the ephemeral keys, creates a secret
int tsl_id_gen_peer_secret(tsl_identity_t *id, tsl_identity_t *peer); // returns the ID of the key (up to TSL_MAX_SECRETS)

// pass secret = NULL to load the ec secret
int tsl_id_load_secret(tsl_identity_t *id, char *secret);

int tsl_id_sym_cipher(tsl_identity_t *id, void *data, size_t, void *ciphertext, size_t*);
int tsl_id_sym_decipher(tsl_identity_t *id, void *ciphertext, size_t, void *data, size_t*);
int tsl_id_hmac(tsl_identity_t *id, void *data, size_t dlen, void *out, size_t *olen); // uses loaded key

int tsl_hash(void *data, size_t dlen, void *hashed, size_t *hlen);

int tsl_base64_decode(char *data, size_t dlen, char *out, size_t *olen);
int tsl_base64_encode(char *data, size_t dlen, char *out, size_t *olen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TCP_SOCKET_LIB_GUARD_ */
