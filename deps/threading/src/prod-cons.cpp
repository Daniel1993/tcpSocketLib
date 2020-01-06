#include "prod-cons.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "util.h"

#define PROD_CONS_ATOMIC_INC_PTR(ptr, nb_items) ({ \
  __typeof__(ptr) readPtr;\
  readPtr = __sync_fetch_and_add(&(ptr), 1); \
  readPtr = LOG_MOD2(readPtr, nb_items); \
  readPtr; \
}) \
// PROD_CONS_ATOMIC_INC_PTR

#define BUFFER_EVENTS        0x80
#define MAX_FREE_NODES       0x100
#define MAX_PROD_CONS_THRS   8

#define LOG_MOD2(idx, mod)     ((long long)(idx) & ((mod) - 1))
#define PTR_MOD(ptr, inc, mod) LOG_MOD2((long long)ptr + (long long)inc, mod)
#define BUFFER_ADDR(pc, ptr)   &(pc->buffer[ptr])
#define IS_EMPTY(pc)           (pc->c_ptr == pc->p_ptr)
#define IS_FULL(pc)            (PTR_MOD(pc->c_ptr, -pc->p_ptr, pc->nb_items) == 1)
#define CAS(ptr, old, new)     __sync_bool_compare_and_swap(ptr, old, new)

// TODO: allow more than one buffer
struct prod_cons_ {
  void      **buffer;
  long long   c_ptr, p_ptr;
  thr_sem_t   c_sem, p_sem;
  size_t      nb_items;
};

// --------------------
// Variables
static int is_stop;
static prod_cons_s *pc[MAX_PROD_CONS_THRS];
static int nbPCs = 0;
static unsigned long freeNodesPtr, freeNodesEndPtr;
static prod_cons_async_req_s reqsBuffer[MAX_FREE_NODES];
// --------------------

prod_cons_s* prod_cons_init(int nb_items)
{
  prod_cons_s *res;
  size_t nbItems = nb_items;

  if (__builtin_popcountll(nb_items) != 1) {
    // not power 2 (more than 1 bit set to 1)
    nbItems = 1 << __builtin_lroundf(__builtin_ceill(__builtin_log2l(nb_items)));
  }

  malloc_or_die(res, 1);
  malloc_or_die(res->buffer, nbItems);
  memset(res->buffer, 0, nbItems*sizeof(void*));
  thr_sem_init(res->c_sem, 0); // consumer blocks at the begining
  thr_sem_init(res->p_sem, nbItems); // producer is free
  res->nb_items = nbItems;
  res->c_ptr = 0;
  res->p_ptr = 0;
  return res;
}

void prod_cons_destroy(prod_cons_s *pc)
{
  thr_sem_destroy(pc->c_sem);
  thr_sem_destroy(pc->p_sem);
  free(pc->buffer);
  free(pc);
}

long prod_cons_produce(prod_cons_s *pc, void *i)
{
  long readPtr;
  if (i == NULL) return -1; // error
  thr_sem_wait(pc->p_sem);
  readPtr = PROD_CONS_ATOMIC_INC_PTR(pc->p_ptr, pc->nb_items);
  while (*BUFFER_ADDR(pc, readPtr) != NULL);
  *BUFFER_ADDR(pc, readPtr) = i;
  thr_sem_post(pc->c_sem); // memory barrier
  return readPtr;
}

long prod_cons_consume(prod_cons_s *pc, void **i)
{
  long readPtr;
  thr_sem_wait(pc->c_sem);
  readPtr = PROD_CONS_ATOMIC_INC_PTR(pc->c_ptr, pc->nb_items);
  while ((*i = *BUFFER_ADDR(pc, readPtr)) == NULL);
  *BUFFER_ADDR(pc, readPtr) = NULL; // reset value
  thr_sem_post(pc->p_sem); // memory barrier
  return readPtr;
}

int prod_cons_count_items(prod_cons_s *pc) {
  return PTR_MOD(pc->p_ptr, -pc->c_ptr, pc->nb_items); // TODO
}

int prod_cons_is_full(prod_cons_s *pc) {
  return IS_FULL(pc);
}

int prod_cons_is_empty(prod_cons_s *pc) {
  return IS_EMPTY(pc);
}

void prod_cons_async_request(prod_cons_async_req_s req, int idAsync)
{
  prod_cons_async_req_s *m_req;
  long idx = PROD_CONS_ATOMIC_INC_PTR(freeNodesPtr, MAX_FREE_NODES);
  // wait release space (else use a malloc/free solution)
  reqsBuffer[idx].fn   = req.fn;
  reqsBuffer[idx].args = req.args;
  m_req = &reqsBuffer[idx];
  prod_cons_produce(pc[idAsync], m_req);
}

// Producer-Consumer thread: consumes requests from the other ones
int prod_cons_init_main_thread()
{
  int pcIdx = __sync_fetch_and_add(&nbPCs, 1);
  if (pcIdx > MAX_PROD_CONS_THRS) return -1;
  pc[pcIdx] = prod_cons_init(BUFFER_EVENTS);
  return pcIdx;
}

void prod_cons_stop_all_threads()
{
  is_stop = 1;
  __sync_synchronize();
  for (int i = 0; i < nbPCs; ++i) {
    prod_cons_async_request((prod_cons_async_req_s){
      .args = NULL,
      .fn = NULL
    }, i);
  }
}

void prod_cons_destroy_all_threads()
{
  int allPCs = nbPCs;
  int pcs = allPCs > MAX_PROD_CONS_THRS ? MAX_PROD_CONS_THRS : allPCs;
  for (int i = 0; i < pcs; ++i) {
    prod_cons_destroy(pc[i]);
  }
  nbPCs = 0;
  is_stop = 0;
}

void* prod_cons_main_thread(void *arg)
{
  intptr_t pcIdx = (intptr_t)arg;
  prod_cons_async_req_s *req;

  while (!is_stop || !prod_cons_is_empty(pc[pcIdx])) {
    prod_cons_consume(pc[pcIdx], (void**)&req);
    PROD_CONS_ATOMIC_INC_PTR(freeNodesEndPtr, MAX_FREE_NODES);
    if (req->fn != NULL) req->fn(req->args, pcIdx);
    // if malloc'ing the request free it here
  }
  return NULL;
}
