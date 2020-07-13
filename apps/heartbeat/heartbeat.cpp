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
Server *server;

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

int handle_nodes(const char *inputArg)
{
  char buffer[1024];
  string arg(inputArg);

  if (arg.rfind("node", 0) == 0) {
    if (input_getString((char *)inputArg, buffer) > 1024) {
      printf("buffer overflow!\n");
      return 1;
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

    RemoteEntity entity(arg, addr, atoi(port.c_str()));

    entity.LoadId();
    if (!entity.VerifyId(caCert)) {
      printf("[ERROR]: verification of %s cert failed\n", arg.c_str());
    }
    
    otherNodes[arg] = make_tuple(addr, port, entity, 0 /* xch_key */, 0);
    printf("%s: addr = %s, port = %s, public key = %s\n",
      arg.c_str(), addr.c_str(), port.c_str(), publKey.c_str());
  }
  return 0;
}

int exchangeKeyCallback(Message &msg)
{
  envelope_s response;
  long size;
  envelope_s *castMsg = (envelope_s*)msg.GetContents(size);
  char responseOk[] = "ok";
  char responseNOk[] = "not-ok";
  RemoteEntity otherId;
  RemoteEntity otherKey;

  if (size != sizeof(envelope_s)) {
    printf("error, message size mismatch (got %zu B, expected %zu B)\n", sizeof(envelope_s), size);
    Message resp((unsigned char*)responseNOk, (size_t)sizeof(responseNOk));
    msg.RespondWith(resp);
    return 1;
  }

  // exchange key with node
  string otherNode = string(castMsg->msg.from);
  otherId = get<2>(otherNodes[otherNode]);

  if (!otherId.VerifyMsg(msg)) {
    printf("[ERROR]: signature failed!\n"); // TODO: abort program
  }

  auto tuple = otherNodes[otherNode];
  otherNodes[string(castMsg->msg.from)] = make_tuple(get<0>(tuple), get<1>(tuple), get<2>(tuple), 1, get<4>(tuple));

  otherKey.DeserlKey(castMsg->msg.text, 2048);
  otherId.PairWithKey(otherKey.GetId());

  memcpy(response.msg.text, responseOk, strlen(responseOk));
  response.msg.header.type = ACK;

  Message resp((unsigned char*)&response, sizeof(envelope_s));

  msg.RespondWith(resp);

  printf("[XCH]: got pub_key from %s!\n", otherNode.c_str());
  // end of manage key

  return 0;
}

int heartbeatCallback(Message &msg)
{
  // normal heartbeat
  long size;
  envelope_s *castMsg = (envelope_s *)msg.GetContents(size);
  string otherNode = string(castMsg->msg.from);
  RemoteEntity otherId = get<2>(otherNodes[otherNode]);
  char responseOk[] = "ok";
  char responseNOk[] = "not-ok";
  envelope_s response;
  if (!get<3>(otherNodes[otherNode])) return 1;

  // tsl_load_publkey((char*)get<3>(otherNodes[string(castMsg->msg.text)]).c_str());
  
  // msg.Verify(otherId.GetId()); // TODO: change between HMAC/Signature
  if (msg.HmacVerify(otherId.GetId())) {
    printf("HMAC verify success!\n");
    
    memcpy(response.msg.text, responseOk, strlen(responseOk));
    response.msg.header.type = ACK;
    Message resp((unsigned char*)&response, sizeof(envelope_s));
    msg.RespondWith(resp);

  } else if (msg.Verify(otherId.GetId())) {
    printf("Signature verify success (no HMAC)!\n");
    
    memcpy(response.msg.text, responseOk, strlen(responseOk));
    response.msg.header.type = ACK;
    Message resp((unsigned char*)&response, sizeof(envelope_s));
    msg.RespondWith(resp);

  } else {
    printf("HMAC && Signature verify fail!\n");

    memcpy(response.msg.text, responseNOk, strlen(responseNOk));
    response.msg.header.type = NACK;
    Message resp((unsigned char*)&response, sizeof(envelope_s));
    msg.RespondWith(resp);

  }
  // end of heartbeat
  return 0;
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

      Message msg((unsigned char*)&env, sizeof(envelope_s));

      msg.Sign(myId->GetId());
      server->SendMsg(msg);
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
      RemoteEntity otherId = get<2>(otherNodes[it->first]);
      Message msg((unsigned char*)&env, sizeof(envelope_s));

      msg.Sign(myId->GetId());
      server->SendMsg(msg);

      // printf("connected (%i)!\n", connId);
      // clock_gettime(CLOCK_MONOTONIC_RAW, &start);
      // tsl_send_msg(connId, (void*)&env, sizeof(envelope_s));
      // tsl_recv_msg(connId, &respOk, &size); // TODO: check message
      // clock_gettime(CLOCK_MONOTONIC_RAW, &end);
      // durationMs = ((end.tv_sec * 1e9 + end.tv_nsec) - (start.tv_sec * 1e9 + start.tv_nsec)) / 1e6f;
      // printf("[%s] response from %s = \"%s\" (type = %i, lat = %.3fms)\n", id, it->first.c_str(),
      //   respOk.msg.text, respOk.msg.header.type, durationMs);
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
  myId->LoadId();

  server = new Server(myId, atoi(port));

  server->AddCallback(0, exchangeKeyCallback);
  server->AddCallback(1, heartbeatCallback);

  caCert = tsl_alloc_identity();
  if (tsl_load_identity(caCert, NULL, NULL, NULL, masterCert, NULL)) {
    printf("Error: %s\n", tsl_last_error_msg);
    return EXIT_FAILURE;
  }
  if (!myId->VerifyId(caCert)) {
    printf("ERROR, master did not certify my key!\n");
  }
  // TODO: send a generated key on first contact
  size_t size = 2048;
  myId->SerlKey(exchangeKey, &size);
  printf("Gen key : \n%s", exchangeKey);
  input_foreach(handle_nodes); // do this only after the previous 3

  printf("%s listening on port %s\n", id, port);

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
