#include "tcpSocketLib.h"
#include "input_handler.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

void handler(void *msg, size_t len, void(*respondWith)(void*,size_t), void(*waitResponse)(void*, size_t*))
{
  printf("[SERVER] got message: %s\n", (char*)msg);
  char buffer[TSL_MSG_BUFFER] = "world!";
  size_t len2 = strlen(buffer)+1;
  respondWith(buffer, len2);
  waitResponse((void*)buffer, &len2);
  printf("[SERVER] got message: %s\n", (char*)buffer);
} 

int main (int argc, char **argv)
{
  char port[64] = "16080";
  char buffer[TSL_MSG_BUFFER] = "hello";
  char buffer2[TSL_MSG_BUFFER] = "bye!";
  size_t len;
  input_parse(argc, argv);
  if (input_exists("PORT")) {
    input_getString("PORT", port); // test size
  }

  printf("openning port %s\n", port);

  tsl_init(port);

  tsl_add_handler(handler);

  int connId = tsl_connect_to("127.0.0.1", port);
  printf("connection = %i\n", connId);
  tsl_send_msg(connId, buffer, strlen(buffer)+1); // do not forget \0
  tsl_recv_msg(connId, (void*)buffer, &len);
  tsl_send_msg(connId, buffer2, strlen(buffer2)+1);
  tsl_close_all_connections();

  printf("[CLIENT]: got message %s\n", (char*)buffer);

  tsl_destroy();

  return EXIT_SUCCESS;
}

