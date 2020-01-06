#include "input_handler.h"
#include "threading.h"
#include "tcpSocketLib.h"

#include <string.h>
#include <string>
#include <map>
#include <tuple>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

using namespace std;

static char port[16] = "16123";
static char privKey[1024];
static char id[64] = "node1";
static map<string,int> secrets;
static map<string,tuple<string, string, int, string>> otherNodes;

typedef enum { HEARTBEAT = 1, ACK, NACK} MSG_TYPE;

typedef struct {
  MSG_TYPE type;
} msg_header_s;

typedef struct {
  msg_header_s header;
  char text[TSL_HASH_SIZE];
} msg_s;

typedef struct {
  msg_s msg;
  unsigned char hmac[TSL_HASH_SIZE];
  unsigned char signature[TSL_SIGNATURE_SIZE];
  size_t signatureSize;
} envelope_s;

static int cmpHmacs(unsigned char *hmac1, unsigned char *hmac2)
{
  // there is a AVX512 instruction that can compare 64 Bytes 
  for (int i = 0; i < TSL_HASH_SIZE; ++i) {
    if (hmac1[i] != hmac2[i]) return 0;
  }
  return 1;
}

int handle_nodes(const char *inputArg)
{
  char buffer[1024];
  string arg(inputArg);

  if (arg.rfind("node", 0) == 0) {
    if (input_getString((char *)inputArg, buffer) > 1024) {
      printf("buffer overflow!\n");
      return 0;
    }
    string value(buffer);
    string addr, port, publKey;
    string delimiter = ",";
    size_t pos = 0;
    void *peerkey = NULL;
    int secretId = -1;

    if ((pos = value.find(delimiter)) == string::npos) return 0;
    addr = value.substr(0, pos);
    value.erase(0, pos + delimiter.length());
    if ((pos = value.find(delimiter)) == string::npos) return 0;
    port = value.substr(0, pos);
    value.erase(0, pos + delimiter.length());
    if (value.length() == 0) return 0;
    publKey = value;

    tsl_load_publkey((char*)publKey.c_str());
    tsl_get_ec_from_pubkey(&peerkey);
    tsl_serialize_ec_pubkey(peerkey, buffer, 1024);
    secretId = tsl_create_secret(peerkey);

    otherNodes.insert(make_pair(arg, make_tuple(addr, port, secretId, publKey)));
    printf("%s: addr = %s, port = %s, public key = %s, secretId = %i\n",
      arg.c_str(), addr.c_str(), port.c_str(), publKey.c_str(), secretId);
  }
  return 0;
}

void heartbeat(void *msg, size_t len, void(*respondWith)(void*,size_t), void(*waitResponse)(void*, size_t*))
{
  envelope_s response;
  envelope_s *castMsg = (envelope_s*)msg;
  unsigned char hmac[TSL_HASH_SIZE];
  size_t size;
  char responseOk[] = "ok";
  char responseNOk[] = "not-ok";
  int cmp = 0, verify = 0;
  if (len != sizeof(envelope_s)) {
    printf("error, message size mismatch (got %zu B, expected %zu B)\n", sizeof(envelope_s), len);
    respondWith(responseNOk, sizeof(responseNOk));
    return;
  }
  memset(&response, 0, sizeof(response));
  tsl_load_secret(get<2>(otherNodes[string(castMsg->msg.text)]));
  tsl_load_publkey((char*)get<3>(otherNodes[string(castMsg->msg.text)]).c_str());
  tsl_hmac(&(castMsg->msg), sizeof(msg_s), hmac, &size);
  verify = tsl_verify(&(castMsg->signature), castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
  cmp = cmpHmacs((unsigned char*)castMsg->hmac, (unsigned char*)hmac);
  printf("[%s:heartbeat]: \"%s\" (type = %i, hmac = %i, signature = %i)\n", id,
    castMsg->msg.text, castMsg->msg.header.type, cmp, verify);
  if (cmp) {
    memcpy(response.msg.text, responseOk, strlen(responseOk));
    response.msg.header.type = ACK;
  } else {
    memcpy(response.msg.text, responseNOk, strlen(responseNOk));
    response.msg.header.type = NACK;
  }
  respondWith((void*)&response, sizeof(response));
}

void sigIntHandler_fn(int s){
  tsl_destroy();
  exit(EXIT_FAILURE); 
}

void timer_handler(void *arg)
{
  // send messages to all each 1 second
  for (auto it = otherNodes.begin(); it != otherNodes.end(); ++it) {
    envelope_s env;
    envelope_s respOk;
    size_t size;
    struct timespec start, end;
    float durationMs;
    // printf("connecting to %s ... ", it->first.c_str());
    int connId = tsl_connect_to((char*)get<0>(it->second).c_str(), (char*)get<1>(it->second).c_str());
    if (connId == -1)
    {
      // printf("can't connect, no connections available\n");
      continue;
    }
    else if (connId == -2)
    {
      // printf("can't connect, error address format\n");
      continue;
    }
    else if (connId == -3)
    {
      // printf("can't connect, error on socket (maybe offline)\n");
      continue;
    }
    memset(&env, 0, sizeof(env));
    memset(&respOk, 0, sizeof(respOk));
    memcpy(env.msg.text, id, sizeof(id));
    env.msg.header.type = HEARTBEAT;
    tsl_load_secret(get<2>(otherNodes[it->first]));
    tsl_load_secret(get<2>(otherNodes[it->first]));
    tsl_hmac(&(env.msg), sizeof(msg_s), env.hmac, &size);
    if (size > TSL_HASH_SIZE) printf("hmac buffer overflow!\n");
    env.signatureSize = TSL_SIGNATURE_SIZE;
    tsl_sign(&(env.msg), sizeof(msg_s), env.signature, &(env.signatureSize));
    if (env.signatureSize > TSL_SIGNATURE_SIZE) printf("signature buffer overflow!\n");

    // printf("connected (%i)!\n", connId);
    tsl_send_msg(connId, (void*)&env, sizeof(envelope_s));

    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    tsl_recv_msg(connId, &respOk, &size); // TODO: check message
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    durationMs = ((end.tv_sec * 1e9 + end.tv_nsec) - (start.tv_sec * 1e9 + start.tv_nsec)) / 1e6f;
    printf("[%s] response from %s = \"%s\" (type = %i, lat = %.3fms)\n", id, it->first.c_str(),
      respOk.msg.text, respOk.msg.header.type, durationMs);
  }
  tsl_close_all_connections();
  // sleep(5);
  threading_timer(5000, timer_handler, NULL);
}

int main(int argc, char **argv)
{
  struct sigaction sigIntHandler;
  char inputKEY[] = "KEY";
  char inputPORT[] = "PORT";
  char inputID[] = "ID";

  input_parse(argc, argv);

  if (!input_exists(inputKEY)) {
    printf("use ID=nodeZ PORT=portXYZ KEY=<path_to_privkey> nodeX=addrX,portX,certkeyX nodeY=addrY,portY,certkeyY ...\n");
    return EXIT_FAILURE;
  }

  input_getString(inputKEY, privKey);
  if (tsl_load_privkey(privKey)) {
    printf("Error: %s\n", tsl_last_error_msg);
    return EXIT_FAILURE;
  }
  if (input_exists(inputPORT)) {
    input_getString(inputPORT, port);
  }
  if (input_exists(inputID)) {
    if (input_getString(inputID, id) > 64) printf("buffer overflow node ID name\n");
  }
  input_foreach(handle_nodes); // do this only after the previous 3

  printf("%s listening on port %s\n", id, port);

  tsl_init(port);
  tsl_add_handler(heartbeat);

  sigIntHandler.sa_handler = sigIntHandler_fn;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;
  sigaction(SIGINT, &sigIntHandler, NULL);

  threading_timer(5000, timer_handler, NULL);
  while (1) {
    sleep(1); // or accept input
  }

  tsl_destroy(); // should never get here, this is called in SIGINT handler
  return EXIT_SUCCESS;
}
