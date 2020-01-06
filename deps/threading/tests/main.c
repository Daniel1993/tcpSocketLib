#include "prod-cons.h"
#include "threading.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>


static void callback(void *arg, int idx) {
  printf("Hello from thread %i! (%p)\n", idx, arg);
}

static void callback2(int id, int nb_thrs, void *arg) {
  for (int i = 0; i < 5; ++i) {
    printf("%i/%i hello %i!\n", id, nb_thrs, i);
  }
}

int main ()
{
  prod_cons_start_thread();

  // sends three requests, note the requests are serialized
  for (long i = 0; i < 0x20; ++i) {
    prod_cons_async_request((prod_cons_async_req_s){
      .args = (void*)i,
      .fn = callback
    }, 0);
  }

  prod_cons_join_threads();

  printf(" --------------------------------------- \n");

  int id1, id2;
  id1 = prod_cons_start_thread(); // allocates two
  id2 = prod_cons_start_thread();

  assert(id1 == 0);
  assert(id2 == 1);

  // sends three requests, note the requests are serialized
  for (long i = 0; i < 0x20; ++i) {
    prod_cons_async_request((prod_cons_async_req_s){
      .args = (void*)(i + id1*0x20),
      .fn = callback
    }, id1);
    prod_cons_async_request((prod_cons_async_req_s){
      .args = (void*)(i + id2*0x20),
      .fn = callback
    }, id2);
  }

  prod_cons_join_threads();

  printf(" --------------------------------------- \n");

  threading_start(5, 0, callback2, NULL);

  threading_join();

  return EXIT_SUCCESS;
}
