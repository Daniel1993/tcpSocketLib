#include "tcpSocketLib.h"
#include "input_handler.h"

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

int main (int argc, char **argv)
{
  char publKey[128] = "publ.pem";
  char publKey2[128] = "publ2.pem";
  char privKey[128] = "priv.pem";
  char privKey2[128] = "priv2.pem";
  char publKeyCsr[128] = "publ.csr";
  char publKeyCsr2[128] = "publ2.csr";
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

  tsl_create_keys(privKey, publKey, publKeyCsr, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "subjectOrg",
    .unit = "subjectOrgUnit",
    .commonName = "subject",
    .email = "subject@com.pt"
  });

  tsl_load_privkey(privKey);
  tsl_load_publkey(publKey);

  tsl_create_self_signed_cert(publKeyCrt1, 500, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "myOrganization",
    .unit = "myOrgUnit",
    .commonName = "myCommonName",
    .email = "my_email@com.pt"
  });

  tsl_load_cert(publKeyCrt1);

  len = 512;
  tsl_load_privkey(privKey); // must have the correct key!
  if (tsl_sign(msg, msgLen, (void**)&signature, &len)) {
    printf("error signing: %s\n", tsl_last_error_msg);
  }

  tsl_base64_encode(signature, len, signatureBase64, &signatureBase64Size);
  tsl_load_publkey(publKey);
  printf("msg = %s signed to %s (len=%lu) verify = %i\n", msg,
    signatureBase64, len, tsl_verify(signature, len, msg, msgLen));
  
  printf("tsl_cert(publKeyCrt2 ...)\n");
  tsl_cert(publKeyCrt2, publKeyCsr, 500, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "issuerOrg",
    .unit = "issuerOrgUnit",
    .commonName = "issuer",
    .email = "issuer@com.pt"
  });

  printf("tsl_load_cert(publKeyCrt2)\n");
  tsl_load_cert(publKeyCrt2);

  printf("tsl_cert_get_issuer(...)\n");
  tsl_cert_get_issuer(&fields);
  printf("issuer = %s\n", fields.commonName);

  tsl_cert_get_subject(&fields);
  printf("subject = %s\n", fields.commonName);

  msgLen = strlen(msg);
  tsl_sign(msg, msgLen, (void**)&signature, &cipLen);

  printf("Message = %s\n", msg);
  
  tsl_load_privkey(privKey); // must have the correct key!
  len = 512;
  if (tsl_sign(msg, msgLen, (void**)&signature, &len)) {
    printf("error signing: %s\n", tsl_last_error_msg);
  }
  tsl_base64_encode(signature, len, signatureBase64, &signatureBase64Size);

  printf("Signed message = %s (%zu B, verify = %i)\n", signatureBase64, len,
    tsl_verify(signature, len, msg, msgLen));

  int isValid = tsl_cert_check_date_valid(signature, cipLen, msg, msgLen);
  printf("Certificarte date is valid = %i\n", isValid);

  tsl_destroy();

  // -------------------------------
  // creates a new key and uses the previous as peer-key
  tsl_create_keys(privKey2, publKey2, publKeyCsr2, (tsl_csr_fields_t){
    .country = "PT",
    .state = "PT",
    .locality = "Lisbon",
    .org = "subjectOrg",
    .unit = "subjectOrgUnit",
    .commonName = "subject",
    .email = "subject@com.pt"
  });

  void *eckey = NULL;
  void *eckeyDes = NULL;
  char serializeEckey[8192];
  char cipher1[8192];
  size_t cipher_size;
  void *eckey2 = NULL; // repeat with new key, should give the same secret
  void *eckeyDes2 = NULL;
  char serializeEckey2[8192];
  char decipher2[8192];
  size_t msg_size;

  tsl_load_privkey(privKey);
  tsl_get_ec_key(&eckey); // from private key
  tsl_serialize_ec_pubkey(eckey, (void*)serializeEckey, 8192);
  tsl_deserialize_ec_pubkey((void*)serializeEckey, 8192, &eckeyDes);

  tsl_load_privkey(privKey2);
  tsl_create_secret(eckeyDes); // should return 0
  tsl_load_secret(0);
  tsl_sym_cipher(msg, strlen(msg), cipher1, &cipher_size);

  tsl_load_privkey(privKey2);
  tsl_get_ec_key(&eckey2); // from private key
  tsl_serialize_ec_pubkey(eckey2, (void*)serializeEckey2, 8192);
  tsl_deserialize_ec_pubkey((void*)serializeEckey2, 8192, &eckeyDes2);

  tsl_load_privkey(privKey);
  tsl_create_secret(eckeyDes2); // should return 1
  tsl_load_secret(1);
  tsl_sym_decipher(cipher1, cipher_size, decipher2, &msg_size);

  printf("msg = %s, decipher = %s\n", msg, decipher2);

  char hmac[1024];
  char hmacBase64[1024];
  size_t hmacSize;
  size_t hmacBase64Size;
  tsl_hmac(msg, strlen(msg), hmac, &hmacSize);
  tsl_base64_encode(hmac, hmacSize, hmacBase64, &hmacBase64Size);
  printf("msg = %s, hmac = %s (%zu Bytes)\n", msg, hmacBase64, hmacSize);

  return EXIT_SUCCESS;
}

