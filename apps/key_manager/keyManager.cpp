#include "input_handler.h"
#include "tcpServer.hpp"

#include <string.h>

#define BUFFER_SIZE    2048
#define FILE_NAME_SIZE   64
#define DAYS_VALID     9999

using namespace std;
using namespace tcpsrv;

#define snprintf_nowarn(...) (snprintf(__VA_ARGS__) < 0 ? abort() : (void)0)

int main(int argc, char **argv)
{
  char operation[BUFFER_SIZE];
  char name[BUFFER_SIZE];
  char privKeyFile[BUFFER_SIZE];
  char inputOPERATION[] = "OPERATION";
  char inputNAME[] = "NAME";
  Entity *id;

  input_parse(argc, argv);
  if (!input_exists(inputOPERATION)) {
    printf("set OPERATION=<CREATE_MASTER_KEY|CREATE_KEY>\n");
    printf("    NAME=<node_name>\n");
    printf("    (master key must be in ./master_priv_key with CREATE_KEY)\n");
    printf("    TODO: fields for the certificate\n");
    return EXIT_FAILURE;
  }

  if (input_getString(inputOPERATION, operation) > BUFFER_SIZE-FILE_NAME_SIZE ||
      input_getString(inputNAME, name) > BUFFER_SIZE-FILE_NAME_SIZE) {
    printf("buffer overflow\n");
    return EXIT_FAILURE;
  }

  // tsl_csr_fields_t fields;
  // memset(&fields, '\0', sizeof(fields));

  // snprintf_nowarn(privKeyFile,  BUFFER_SIZE, "%s/%s", dirPriv, "priv_key.pem"       );
  // snprintf_nowarn(publKeyFile,  BUFFER_SIZE, "%s/%s", dirPubl, "publ_key.pem"       );
  // snprintf_nowarn(publCertFile, BUFFER_SIZE, "%s/%s", dirPubl, "cert_publ_key.pem"  );
  // snprintf_nowarn(publCsrFile,  BUFFER_SIZE, "%s/%s", dirPubl, "csr.pem"            );

  // id = tsl_alloc_identity();
  // tsl_id_create_keys(id, 1, fields);

  if (strcmp(operation, "CREATE_MASTER_KEY") == 0) {
    id = new Entity("master");
    id->CreateKeyPair(3);

  } else if (strcmp(operation, "CREATE_KEY") == 0) {
    Entity master("master");
    id =  new Entity(string(name));

    id->CreateKeyPair(3);
    
    master.CertKey(*id, 365);

  } else {
    printf("Wrong OPERATION, use CREATE_MASTER_KEY or CREATE_KEY\n");
    return EXIT_FAILURE;
  }
  id->StoreId();

  delete id;

  return EXIT_SUCCESS;
}
