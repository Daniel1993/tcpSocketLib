#include "tcpSocketLib.h"
#include "threading.h"

#include <stdio.h> 
#include <errno.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <unistd.h>
#include <stdint.h>
#include <openssl/ssl.h>

__thread char tsl_last_error_msg[1024];

typedef struct buffer_t {
  size_t size;
  int connfd;
  void *ptr;
} buffer_t;

static tsl_handler_t handlers[TSL_MAX_HANDLERS];
static int nbHandlers = 0;
static volatile int isServerOn = 0;
static int isExit = 0;
static volatile int isServerSet = 0;
static char serverPort[64] = "0";

__thread int clientConnections[TSL_MAX_CONNECTIONS];
__thread int nbClientConnections = 0;
__thread buffer_t *currBuffer;

#define INIT_ERROR_CHECK() \
  intptr_t _err; \
//
#define ERROR_CHECK(call, teardown) \
_err = (intptr_t)(call); \
if (_err < 0) { \
  TSL_ADD_ERROR("[%s:%i] %s", __FILE__, __LINE__, strerror(errno)); \
  teardown; \
} \
//

// respond callback
static void respondWith(void *packet, size_t len)
{
  char sendTmpBuffer[TSL_MSG_BUFFER]; 
  size_t base64Size;
  INIT_ERROR_CHECK();
  tsl_base64_encode((char*)packet, len, sendTmpBuffer, &base64Size);
  ERROR_CHECK(write(currBuffer->connfd, sendTmpBuffer, base64Size), { return; });
  fsync(currBuffer->connfd);
}

// buffer must have size TSL_MSG_BUFFER
static void waitResponse(void *packet, size_t *len)
{
  char recvTmpBuffer[TSL_MSG_BUFFER]; 
  size_t base64decodeSize;
  INIT_ERROR_CHECK();
  ERROR_CHECK((*len = read(currBuffer->connfd, recvTmpBuffer, TSL_MSG_BUFFER)), { return; });
  tsl_base64_decode(recvTmpBuffer, *len, (char*)packet, &base64decodeSize);
  *len = base64decodeSize;
}

static void handler_fn(void *arg, int idx)
{
  currBuffer = (buffer_t*)arg;
  for (int i = 0; i < nbHandlers; i++) {
    handlers[i](currBuffer->ptr, currBuffer->size, respondWith, waitResponse); // waits for the handler
  }
  free(currBuffer->ptr);
  free(arg);
}

static void server(int id, int nbThreads, void *arg)
{
  char recvTmpBuffer[TSL_MSG_BUFFER]; // TODO: this must be aligned 
  int retError = 1;
  int socketfd, connfd;
  size_t base64len;
  const struct sockaddr_in servaddr = {
    .sin_family = AF_INET,
    .sin_port = htons(atol(serverPort)),
    .sin_addr = { .s_addr = htonl(INADDR_ANY) }
  }, cli;
  const struct sockaddr_in servaddr_read;
  socklen_t len;
  INIT_ERROR_CHECK();

  ERROR_CHECK((socketfd = socket(AF_INET, SOCK_STREAM, 0)), { goto ret; });
  ERROR_CHECK(bind(socketfd, (struct sockaddr*)&servaddr, sizeof(servaddr)), { goto ret; });
  ERROR_CHECK(getsockname(socketfd, &servaddr_read, sizeof(servaddr_read)), { goto ret; });
  sprintf(serverPort, "%ui", ntohs(servaddr_read.sin_port));
  ERROR_CHECK(listen(socketfd, TSL_MSG_QUEUE_SIZE), { goto ret; });

  isServerOn = 1;
  while (!isExit) { 
    ERROR_CHECK((connfd = accept(socketfd, (struct sockaddr*)&cli, &len)), {
      fprintf(stderr, "%s\n", tsl_last_error_msg); continue;
    });

    // copy data
    void *data = malloc(sizeof(buffer_t));
    ((buffer_t*)data)->connfd = connfd;

    ERROR_CHECK((base64len = read(connfd, (void*)recvTmpBuffer, TSL_MSG_BUFFER)), {
      fprintf(stderr, "%s\n", tsl_last_error_msg); continue;
    });
    ((buffer_t*)data)->ptr = malloc(base64len); // allocs a bit more than needed (base64 inflates data)
    tsl_base64_decode(recvTmpBuffer, base64len, ((buffer_t*)data)->ptr, &(((buffer_t*)data)->size));

    // handle
    threading_async(0, handler_fn, data);
  }
  ERROR_CHECK(close(socketfd), { goto ret; });

  retError = 0;
ret:
  if (retError) {
    isServerSet = 0;
    fprintf(stderr, "ERROR %s \n", tsl_last_error_msg);
  }
}

int tsl_init(char *port)
{
  if (isServerSet) {
    return -2;
  }
  if (port != NULL) {
    memcpy(serverPort, port, strlen(port));
  }
  isServerSet = 1;
  threading_start(1/* server */, TSL_HANDLER_THREADS/* handler */, server, NULL);
  while (!isServerOn);
  SSL_library_init();
  SSL_load_error_strings();

  return 0;
}

int tsl_check_port()
{
  return atoi(serverPort);
}

int tsl_destroy()
{
  isExit = 1;
  // send msg to localhost:port to wake the server
  if (isServerSet) {
    tsl_close_all_connections();
    int connection = tsl_connect_to("127.0.0.1", serverPort);
    int nullMsg = 0;
    tsl_send_msg(connection, &nullMsg, sizeof(int));
    tsl_close_all_connections();
  }

  threading_join();
  return 0;
}

int tsl_connect_to(char *addr, char *port)
{
  INIT_ERROR_CHECK();
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s, conn;

  if (nbClientConnections >= TSL_MAX_CONNECTIONS) {
    TSL_ADD_ERROR("Reached maximum number of connections");
    return -1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  s = getaddrinfo(addr, port, &hints, &result);
  if (s != 0) {
    TSL_ADD_ERROR("getaddrinfo: %s", gai_strerror(s));
    return -2;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if ((clientConnections[nbClientConnections] = sfd) == -1) continue;
    if ((conn = connect(sfd, rp->ai_addr, rp->ai_addrlen)) != -1) break; /* Success */
  }

  ERROR_CHECK(sfd, { return -3; });
  ERROR_CHECK(conn, { return -3; });
  nbClientConnections++;
  return nbClientConnections-1;
}

int tsl_close_all_connections()
{
  for (int i = 0; i < nbClientConnections; ++i) {
    close(clientConnections[i]);
  }
  nbClientConnections = 0;
  return 0;
}

int tsl_send_msg(int connId, void *msg, size_t len)
{
  char sendTmpBuffer[TSL_MSG_BUFFER]; 
  size_t base64Size;
  INIT_ERROR_CHECK();
  tsl_base64_encode((char*)msg, len, sendTmpBuffer, &base64Size);
  ERROR_CHECK(write(clientConnections[connId], sendTmpBuffer, base64Size),  { return -1; });
  fsync(clientConnections[connId]);
  return 0;
}

int tsl_recv_msg(int connId, void *msg, size_t *len)
{
  char recvTmpBuffer[TSL_MSG_BUFFER]; 
  size_t base64decodeSize;
  INIT_ERROR_CHECK();
  ERROR_CHECK((*len = read(clientConnections[connId], recvTmpBuffer, TSL_MSG_BUFFER)),  { return -1; });
  tsl_base64_decode(recvTmpBuffer, *len, (char*)msg, &base64decodeSize);
  *len = base64decodeSize;
  return 0;
}

// handlers are added in order
int tsl_add_handler(tsl_handler_t handler)
{
  if (nbHandlers < TSL_MAX_HANDLERS) {
    handlers[nbHandlers] = handler;
    nbHandlers++;
  } else {
    // error, out of space
    return -1;
  }
  return 0;
}
