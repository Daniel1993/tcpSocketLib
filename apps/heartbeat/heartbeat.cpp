#include "input_handler.h"
#include "threading.h"
#include "tcpServer.hpp"

#include <string.h>
#include <string>
#include <map>
#include <tuple>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

using namespace std;
using namespace tcpsrv;

static char port[16] = "16123";
static char id[64] = "node1";
static char masterCert[1024];
static char privKey[1024];
static char exchangeKey[2048];
static map<string,int> secrets;
static map<string, tuple<string, string, RemoteEntity, int, int>> otherNodes;
Entity *myId;
tsl_identity_t *caCert;

typedef enum { HEARTBEAT = 1, ACK, NACK, KEY_XCH } MSG_TYPE;

typedef struct {
  MSG_TYPE type;
} msg_header_s;

typedef struct {
  msg_header_s header;
  char from[128];
  char text[2048];
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

    if ((pos = value.find(delimiter)) == string::npos) return 0;
    addr = value.substr(0, pos);
    value.erase(0, pos + delimiter.length());
    if ((pos = value.find(delimiter)) == string::npos) return 0;
    port = value.substr(0, pos);
    value.erase(0, pos + delimiter.length());
    if (value.length() == 0) return 0;
    publKey = value;

    Entity entity(arg, addr, atoi(port.c_str()));

    entity.SetLocalKeys(publKey);
    entity.LoadId();
    if (!entity.VerifyId(masterCert)) {
      printf("[ERROR]: verification of %s cert failed\n", arg.c_str());
    }
    
    otherNodes[arg] = make_tuple(addr, port, entity, 0 /* xch_key */, 0);
    printf("%s: addr = %s, port = %s, public key = %s\n",
      arg.c_str(), addr.c_str(), port.c_str(), publKey.c_str());
  }
  return 0;
}

void exchangeKeyCallback(Message msg)
{
  envelope_s response;
  long size;
  envelope_s *castMsg = (envelope_s*)msg.GetContents(size);
  unsigned char hmac[TSL_HASH_SIZE];
  char responseOk[] = "ok";
  char responseNOk[] = "not-ok";
  int cmp = 0, verify = 0;
  RemoteEntity otherId;

  if (size != sizeof(envelope_s)) {
    printf("error, message size mismatch (got %zu B, expected %zu B)\n", sizeof(envelope_s), size);
    Message resp((unsigned char*)responseNOk, (size_t)sizeof(responseNOk));
    msg.RespondWith(resp);
    return;
  }

  // exchange key with node
  string otherNode = string(castMsg->msg.from);
  otherId = get<2>(otherNodes[otherNode]);

  verify = otherId.VerifyMsg(msg);
  if (!verify) {
    printf("[ERROR]: signature failed!\n"); // TODO: abort program
  }

  auto tuple = otherNodes[otherNode];
  otherNodes[string(castMsg->msg.from)] = make_tuple(get<0>(tuple), get<1>(tuple), get<2>(tuple), 1, get<4>(tuple));

  RemoteEntity otherKey();
  otherId.DeserlKey(castMsg->msg.text, 2048);
  otherId.PairWithKey(otherKey.GetId());

  memcpy(response.msg.text, responseOk, strlen(responseOk));
  response.msg.header.type = ACK;

  Message resp((unsigned char*)&response, sizeof(envelope_s));

  msg.RespondWith(resp);

  printf("[XCH]: got pub_key from %s!\n", otherNode.c_str());
  // end of manage key
}

void heartbeatCallback(Message msg)
{
  // normal heartbeat
  envelope_s *castMsg = (envelope_s *)msg.GetContents(size);
  string otherNode = string(castMsg->msg.from);
  otherId = get<2>(otherNodes[otherNode]);
    if (!get<3>(otherNodes[otherNode])) return;
  // tsl_load_publkey((char*)get<3>(otherNodes[string(castMsg->msg.text)]).c_str());
  tsl_id_hmac(otherId, &(castMsg->msg), sizeof(msg_s), hmac, &size);
  verify = tsl_id_verify(otherId, &(castMsg->signature),
    castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
  // tsl_verify(&(castMsg->signature), castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
  cmp = cmpHmacs((unsigned char*)castMsg->hmac, (unsigned char*)hmac);
  printf("send_heartbeat_to \"%s\" (type = %i, hmac = %i, signature = %i)\n",
    castMsg->msg.from, castMsg->msg.header.type, cmp, verify);
  if (cmp) {
    memcpy(response.msg.text, responseOk, strlen(responseOk));
    response.msg.header.type = ACK;
  } else {
    memcpy(response.msg.text, responseNOk, strlen(responseNOk));
    response.msg.header.type = NACK;
  }
  // end of heartbeat
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
  tsl_identity_t *otherId;

  if (len != sizeof(envelope_s)) {
    printf("error, message size mismatch (got %zu B, expected %zu B)\n", sizeof(envelope_s), len);
    respondWith(responseNOk, sizeof(responseNOk));
    return;
  }

  memset(&response, 0, sizeof(response));
  if (castMsg->msg.header.type == KEY_XCH)
  {
    // exchange key with node
    string otherNode = string(castMsg->msg.from);
    otherId = get<2>(otherNodes[otherNode]);

    verify = tsl_id_verify(otherId, &(castMsg->signature),
      castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
    if (!verify) {
      printf("[ERROR]: signature failed!\n"); // TODO: abort program
    }

    auto tuple = otherNodes[otherNode];
    otherNodes[string(castMsg->msg.from)] = make_tuple(get<0>(tuple), get<1>(tuple), get<2>(tuple), 1, get<4>(tuple));

    tsl_id_deserialize_ec_pubkey(otherId, castMsg->msg.text, 2048);
    tsl_id_gen_peer_secret(myId, otherId);
    tsl_id_load_secret(otherId, NULL);

    memcpy(response.msg.text, responseOk, strlen(responseOk));
    response.msg.header.type = ACK;
    printf("[XCH]: got pub_key from %s!\n", otherNode.c_str());
    // end of manage key
  }
  else
  {
    // normal heartbeat
    string otherNode = string(castMsg->msg.from);
    otherId = get<2>(otherNodes[otherNode]);
     if (!get<3>(otherNodes[otherNode])) return;
    // tsl_load_publkey((char*)get<3>(otherNodes[string(castMsg->msg.text)]).c_str());
    tsl_id_hmac(otherId, &(castMsg->msg), sizeof(msg_s), hmac, &size);
    verify = tsl_id_verify(otherId, &(castMsg->signature),
      castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
    // tsl_verify(&(castMsg->signature), castMsg->signatureSize, &(castMsg->msg), sizeof(msg_s));
    cmp = cmpHmacs((unsigned char*)castMsg->hmac, (unsigned char*)hmac);
    printf("send_heartbeat_to \"%s\" (type = %i, hmac = %i, signature = %i)\n",
      castMsg->msg.from, castMsg->msg.header.type, cmp, verify);
    if (cmp) {
      memcpy(response.msg.text, responseOk, strlen(responseOk));
      response.msg.header.type = ACK;
    } else {
      memcpy(response.msg.text, responseNOk, strlen(responseNOk));
      response.msg.header.type = NACK;
    }
    // end of heartbeat
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
      // printf("can't connect %s, error on socket (maybe offline)\n", it->first.c_str());
      otherNodes[it->first] = make_tuple(get<0>(it->second), get<1>(it->second), get<2>(it->second), get<3>(it->second), 0);
      continue;
    }

    int xch_key = get<4>(it->second);
    if (!xch_key)
    {
      otherNodes[it->first] = make_tuple(get<0>(it->second), get<1>(it->second), get<2>(it->second), get<3>(it->second), 1);

      memset(&env, 0, sizeof(env));
      memset(&respOk, 0, sizeof(respOk));
      memcpy(env.msg.from, id, sizeof(id));
      memcpy(env.msg.text, exchangeKey, 2048);
      env.msg.header.type = KEY_XCH;
      env.signatureSize = TSL_SIGNATURE_SIZE;
      tsl_id_sign(myId, &(env.msg), sizeof(msg_s), env.signature, &(env.signatureSize));
      if (env.signatureSize > TSL_SIGNATURE_SIZE) printf("signature buffer overflow!\n");
      tsl_send_msg(connId, (void*)&env, sizeof(envelope_s));


      // clock_gettime(CLOCK_MONOTONIC_RAW, &start);
      // tsl_recv_msg(connId, &respOk, &size); // TODO: check message
      // clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    }
    else
    {
      // waits key exchange

      memset(&env, 0, sizeof(env));
      memset(&respOk, 0, sizeof(respOk));
      memcpy(env.msg.from, id, sizeof(id));
      memcpy(env.msg.text, "ping", sizeof(id));
      env.msg.header.type = HEARTBEAT;
      tsl_identity_t *otherId = get<2>(otherNodes[it->first]);
      tsl_id_hmac(otherId, &(env.msg), sizeof(msg_s), env.hmac, &size);
      if (size > TSL_HASH_SIZE) {
        printf("hmac buffer overflow (%s, size=%lu)!\n", tsl_last_error_msg, size);
      }
      env.signatureSize = TSL_SIGNATURE_SIZE;
      tsl_id_sign(myId, &(env.msg), sizeof(msg_s), env.signature, &(env.signatureSize));
      if (env.signatureSize > TSL_SIGNATURE_SIZE) printf("signature buffer overflow!\n");

      // printf("connected (%i)!\n", connId);
      clock_gettime(CLOCK_MONOTONIC_RAW, &start);
      tsl_send_msg(connId, (void*)&env, sizeof(envelope_s));
      tsl_recv_msg(connId, &respOk, &size); // TODO: check message
      clock_gettime(CLOCK_MONOTONIC_RAW, &end);
      durationMs = ((end.tv_sec * 1e9 + end.tv_nsec) - (start.tv_sec * 1e9 + start.tv_nsec)) / 1e6f;
      printf("[%s] response from %s = \"%s\" (type = %i, lat = %.3fms)\n", id, it->first.c_str(),
        respOk.msg.text, respOk.msg.header.type, durationMs);
    }

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
  char inputMASTER[] = "MASTER_CERT";

  input_parse(argc, argv);

  if (!input_exists(inputKEY)) {
    printf("use ID=nodeZ PORT=portXYZ KEY=<path_to_keyfolder> MASTER_CERT=<path_to_cert> nodeX=addrX,portX,certkeyX nodeY=addrY,portY,certkeyY ...\n");
    return EXIT_FAILURE;
  }
  input_getString(inputKEY, privKey);
  input_getString(inputMASTER, masterCert);
  if (input_exists(inputPORT)) {
    input_getString(inputPORT, port);
  }
  if (input_exists(inputID)) {
    if (input_getString(inputID, id) > 64) printf("buffer overflow node ID name\n");
  }

  myId = new Entity();
  myId->SetLocalKeys(privKey);
  myId->LoadId();

  Server server(myId, atoi(port));

  server.AddCallback(0, exchangeKeyCallback);
  server.AddCallback(1, heartbeatCallback);

  if (tsl_load_identity(myId, privKey, NULL, NULL, NULL, NULL)) {
    printf("Error: %s\n", tsl_last_error_msg);
    return EXIT_FAILURE;
  }
  caCert = tsl_alloc_identity();
  if (tsl_load_identity(caCert, NULL, NULL, NULL, masterCert, NULL)) {
    printf("Error: %s\n", tsl_last_error_msg);
    return EXIT_FAILURE;
  }
  if (!tsl_id_cert_verify(myId, caCert, NULL)) {
    printf("ERROR, master did not certify my key!\n");
  }
  // TODO: send a generated key on first contact
  tsl_id_gen_ec_key(myId);
  tsl_id_serialize_ec_pubkey(myId, exchangeKey, 2048);
  printf("Gen key : \n%s", exchangeKey);
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
