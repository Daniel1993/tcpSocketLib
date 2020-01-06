#include "input_handler.h"
#include "tcpSocketLib.h"

#include <string.h>

#define BUFFER_SIZE    1024
#define FILE_NAME_SIZE   64
#define DAYS_VALID     9999

using namespace std;

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

  sprintf(privKeyFile, "%s/%s", dirPriv, "priv_key.pem");
  sprintf(publKeyFile, "%s/%s", dirPubl, "publ_key.pem");
  sprintf(publCertFile, "%s/%s", dirPubl, "cert_publ_key.pem");
  sprintf(publCsrFile, "%s/%s", dirPubl, "csr.pem");

  tsl_create_keys(privKeyFile, publKeyFile, publCsrFile, fields);

  if (strcmp(operation, "CREATE_MASTER_KEY") == 0) {
    tsl_load_privkey(privKeyFile);
    tsl_create_self_signed_cert(publCertFile, DAYS_VALID, fields);
  } else if (strcmp(operation, "CREATE_KEY") == 0) {
    input_getString(inputMASTER_KEY, masterKey);
    tsl_load_privkey(masterKey);
    tsl_create_self_signed_cert(publCertFile, DAYS_VALID, fields);
  } else {
    printf("Wrong OPERATION, use CREATE_MASTER_KEY or CREATE_KEY\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
