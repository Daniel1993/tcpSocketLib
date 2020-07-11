#include "input_handler.h"
#include "tcpSocketLib.h"

#include <string.h>

#define BUFFER_SIZE    2048
#define FILE_NAME_SIZE   64
#define DAYS_VALID     9999

using namespace std;

#define snprintf_nowarn(...) (snprintf(__VA_ARGS__) < 0 ? abort() : (void)0)

int main(int argc, char **argv)
{
  char operation[BUFFER_SIZE];
  char dirPriv[BUFFER_SIZE];
  char dirPubl[BUFFER_SIZE];
  char masterKey[BUFFER_SIZE];
  char privKeyFile[BUFFER_SIZE];
  char publKeyFile[BUFFER_SIZE];
  char publCertFile[BUFFER_SIZE];
  char publCsrFile[BUFFER_SIZE];
  char inputOPERATION[] = "OPERATION";
  char inputDIR_PRIV[] = "DIR_PRIV";
  char inputDIR_PUBL[] = "DIR_PUBL";
  char inputMASTER_KEY[] = "MASTER_KEY";
  tsl_csr_fields_t fields;
  tsl_identity_t *id;

  input_parse(argc, argv);
  if (!input_exists(inputOPERATION) || !input_exists(inputDIR_PRIV) || !input_exists(inputDIR_PUBL)) {
    printf("set OPERATION=<CREATE_MASTER_KEY|CREATE_KEY>\n");
    printf("    DIR_PRIV=<path>\n");
    printf("    DIR_PUBL=<path>\n");
    printf("    MASTER_KEY=<path> (if you want to sign the key with CREATE_KEY)\n");
    printf("    TODO: fields for the certificate\n");
    return EXIT_FAILURE;
  }

  if (input_getString(inputOPERATION, operation) > BUFFER_SIZE-FILE_NAME_SIZE ||
      input_getString(inputDIR_PRIV, dirPriv) > BUFFER_SIZE-FILE_NAME_SIZE ||
      input_getString(inputDIR_PUBL, dirPubl) > BUFFER_SIZE-FILE_NAME_SIZE) {
    printf("buffer overflow\n");
    return EXIT_FAILURE;
  }

  memset(&fields, '\0', sizeof(fields));

  snprintf_nowarn(privKeyFile,  BUFFER_SIZE, "%s/%s", dirPriv, "priv_key.pem"       );
  snprintf_nowarn(publKeyFile,  BUFFER_SIZE, "%s/%s", dirPubl, "publ_key.pem"       );
  snprintf_nowarn(publCertFile, BUFFER_SIZE, "%s/%s", dirPubl, "cert_publ_key.pem"  );
  snprintf_nowarn(publCsrFile,  BUFFER_SIZE, "%s/%s", dirPubl, "csr.pem"            );

  id = tsl_alloc_identity();
  tsl_id_create_keys(id, 1, fields);

  if (strcmp(operation, "CREATE_MASTER_KEY") == 0) {
    tsl_id_create_self_signed_cert(id, DAYS_VALID, fields);
  } else if (strcmp(operation, "CREATE_KEY") == 0) {
    input_getString(inputMASTER_KEY, masterKey);
    tsl_identity_t *master_id = tsl_alloc_identity();
    tsl_load_identity(master_id, masterKey, NULL, NULL, NULL, NULL);
    tsl_id_cert(master_id, id, DAYS_VALID, fields);
    tsl_free_identity(master_id);
  } else {
    printf("Wrong OPERATION, use CREATE_MASTER_KEY or CREATE_KEY\n");
    return EXIT_FAILURE;
  }
  tsl_store_identity(id, privKeyFile, publKeyFile, publCsrFile, publCertFile, NULL);
  tsl_free_identity(id);

  return EXIT_SUCCESS;
}
