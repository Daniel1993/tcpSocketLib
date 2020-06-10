#include "tcpSocketLib.h"
#include "input_handler.h"

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

int main (int argc, char **argv)
{
  char publKey[128] = "publ.pem";
  // char publKey2[128] = "publ2.pem";
  char privKey[128] = "priv.pem";
  // char privKey2[128] = "priv2.pem";
  char publKeyCsr[128] = "publ.csr";
  // char publKeyCsr2[128] = "publ2.csr";
  char publKeyCrt1[128] = "publ1.crt";
  char publKeyCrt2[128] = "publ2.crt";
  char msg[64] = "Hello world!";
  char signature[512];
  char signatureBase64[1024];
  size_t signatureBase64Size;
  size_t len, msgLen = strlen(msg) + 1, cipLen;
  tsl_csr_fields_t fields;

  tsl_init(NULL);

  input_parse(argc, argv);
  if (input_exists("PUBL")) {
    input_getString("PUBL", publKey);
  }

  if (input_exists("PRIV")) {
    input_getString("PRIV", publKey);
  }

  if (input_exists("CSR")) {
    input_getString("CSR", publKeyCsr);
  }

  if (input_exists("CRT1")) {
    input_getString("CRT1", publKeyCrt1);
  }

  if (input_exists("CRT2")) {
    input_getString("CRT2", publKeyCrt2);
  }

  printf("writing keys in %s (public) and %s (private)\n", publKey, privKey);

  tsl_identity_t *id1 = tsl_alloc_identity();
  tsl_identity_t *id2 = tsl_alloc_identity();
  
  fields = (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "subjectOrg",
    .unit = "subjectOrgUnit",
    .commonName = "subject",
    .email = "subject@com.pt"
  };

  tsl_id_create_keys(id1, fields);
  tsl_id_create_keys(id2, fields);

  tsl_id_create_self_signed_cert(id1, 500, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "myOrganization",
    .unit = "myOrgUnit",
    .commonName = "myCommonName",
    .email = "my_email@com.pt"
  });

  len = 512;
  if (tsl_id_sign(id1, msg, msgLen, (void**)&signature, &len)) {
    printf("error signing: %s\n", tsl_last_error_msg);
  }

  tsl_base64_encode(signature, len, signatureBase64, &signatureBase64Size);
  printf("msg = %s signed to %s (len=%lu) verify = %i\n", msg,
    signatureBase64, len, tsl_id_verify(id1, signature, len, msg, msgLen));
  
  printf("tsl_cert(publKeyCrt2 ...)\n");
  tsl_id_cert(id1, id2, 500, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "issuerOrg",
    .unit = "issuerOrgUnit",
    .commonName = "issuer",
    .email = "issuer@com.pt"
  });

  printf("tsl_cert_get_issuer(...)\n");
  tsl_id_cert_get_issuer(id2, &fields);
  printf("issuer = %s\n", fields.commonName);

  tsl_id_cert_get_subject(id2, &fields);
  printf("subject = %s\n", fields.commonName);

  printf("valid cert = %i (should be 1)\n", tsl_id_cert_verify(id2, id1, NULL));

  msgLen = strlen(msg);
  tsl_id_sign(id2, msg, msgLen, (void**)&signature, &cipLen);

  printf("Message = %s\n", msg);
  
  len = 512;
  if (tsl_id_sign(id2, msg, msgLen, (void**)&signature, &len)) {
    printf("error signing: %s\n", tsl_last_error_msg);
  }
  tsl_base64_encode(signature, len, signatureBase64, &signatureBase64Size);

  printf("Signed message = %s (%zu B, verify = %i)\n", signatureBase64, len,
    tsl_id_verify(id2, signature, len, msg, msgLen));

  int isValid = tsl_id_cert_check_date_valid(id2);
  printf("Certificarte date is valid = %i\n", isValid);

  tsl_id_destroy_keys(id2);

  // -------------------------------
  // creates a new key and uses the previous as peer-key
  tsl_id_create_keys(id2, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "subjectOrg",
    .unit = "subjectOrgUnit",
    .commonName = "subject",
    .email = "subject@com.pt"
  });

  // void *eckey = NULL;
  // void *eckeyDes = NULL;
  char serializeEckey1[8192];
  char cipher1[8192];
  size_t cipher_size;
  // void *eckey2 = NULL; // repeat with new key, should give the same secret
  // void *eckeyDes2 = NULL;
  char serializeEckey2[8192];
  char decipher2[8192];
  size_t msg_size;

  tsl_identity_t *id1a = tsl_alloc_identity();
  tsl_identity_t *id2a = tsl_alloc_identity();

  // Node 1 creates a temporary key ...
  tsl_id_gen_ec_key(id1);
  // ... then serializes the public key and sends
  tsl_id_serialize_ec_pubkey(id1, (void*)serializeEckey1, 8192);
  
  // Same for Node 2
  tsl_id_gen_ec_key(id2);
  tsl_id_serialize_ec_pubkey(id2, (void*)serializeEckey2, 8192);
  
  // Node 1 deserializes N2 key
  tsl_id_deserialize_ec_pubkey(id2a, (void*)serializeEckey2, 8192);
  tsl_id_gen_peer_secret(id1, id2a);
  tsl_id_load_secret(id2a, NULL); // Now we can communicate N1->N2
  
  // Same for Node 2
  tsl_id_deserialize_ec_pubkey(id1a, (void*)serializeEckey1, 8192);
  tsl_id_gen_peer_secret(id2, id1a);
  tsl_id_load_secret(id1a, NULL);

  // id1a --> secret of N2 shared with N1
  // id2a --> secret of N1 shared with N2
  
  // N1->N2
  tsl_id_sym_cipher(id2a, msg, strlen(msg), cipher1, &cipher_size);
  tsl_id_sym_decipher(id1a, cipher1, cipher_size, decipher2, &msg_size);

  printf("msg = %s, decipher = %s\n", msg, decipher2);

  char hmac[1024];
  char hmacBase64[1024];
  size_t hmacSize;
  size_t hmacBase64Size;

  tsl_id_hmac(id2a, msg, strlen(msg), hmac, &hmacSize);
  tsl_base64_encode(hmac, hmacSize, hmacBase64, &hmacBase64Size);
  printf("msg = %s, hmac = %s (%zu Bytes)\n", msg, hmacBase64, hmacSize);

  return EXIT_SUCCESS;
}

