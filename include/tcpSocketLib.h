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

typedef void(*tsl_handler_t)(void*,size_t,void(*respondWith)(void*,size_t),void(*waitResponse)(void*, size_t*)); 

int tsl_init(char *port); // port == NULL --> does not create server
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

int tsl_create_keys(char *privFile, char *publFile, char *csrFile, tsl_csr_fields_t subject);
int tsl_load_privkey(char *privFile); // also loads the public key
int tsl_load_publkey(char *publFile);
int tsl_load_cert(char *certFile); // loads cert & the public key
int tsl_cert_get_issuer(tsl_csr_fields_t*); // load first
int tsl_cert_get_subject(tsl_csr_fields_t*); // load first
int tsl_cert_check_date_valid(); // load first, returns 1 on valid, 0 not valid, -1 error
int tsl_release_keys();

int tsl_create_self_signed_cert(char *file, long daysValid, tsl_csr_fields_t subject);

// reads csrFile and writes certFile with the current private key
int tsl_cert(char *certFile, char *csrFile, long daysValid, tsl_csr_fields_t issuer);

// NOTE: programmer must give enough space in buffers, this will not malloc!
// ciphers with private key (consider using a hash)
int tsl_sign(void *data, size_t, void *ciphertext, size_t *clen); // clen --> must containt the size of the buffer
int tsl_verify(void *ciphertext, size_t clen, void *data, size_t dlen); // -1 is an error, 1 is ok, 0 is false

// negotiate secret
int tsl_get_ec_key(void **eckey); // create a "void *eckey = NULL;" then pass &eckey
                                  // gets the loaded EC_KEY, pass it to the tsl_create_secret
int tsl_get_ec_from_pubkey(void **eckey); // gets from loaded public key (e.g., cert)
int tsl_serialize_ec_pubkey(void *eckey, void *buffer, size_t size); // returns a ptr to buffer
int tsl_deserialize_ec_pubkey(void *buffer, size_t size, void **eckey); // pass &eckey, where eckey is void* = NULL
int tsl_create_secret(void *peerkey); // returns the ID of the key (up to TSL_MAX_SECRETS)
int tsl_clear_all_secrets(); // clears all secrets
int tsl_load_secret(int keyid); // use the ID returned in tsl_create_secret

// note: it stores the hash of symkey (and uses the hash)
int tsl_sym_load_key(char *symkey);

// ciphertext is not allocated --> please provide large enough buffer
int tsl_sym_cipher(void *data, size_t, void *ciphertext, size_t*);
int tsl_sym_decipher(void *ciphertext, size_t, void *data, size_t*);

int tsl_hash(void *data, size_t dlen, void *hashed, size_t *hlen);
int tsl_hmac(void *data, size_t dlen, void *out, size_t *olen); // uses loaded key

int tsl_base64_decode(char *data, size_t dlen, char *out, size_t *olen);
int tsl_base64_encode(char *data, size_t dlen, char *out, size_t *olen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TCP_SOCKET_LIB_GUARD_ */
