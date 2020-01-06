#ifndef CP_H_GUARD
#define CP_H_GUARD

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct prod_cons_ prod_cons_s;

typedef void(*prod_cons_req_fn)(void*, int asyncId);

typedef struct prod_cons_async_req_ {
  void *args;
  prod_cons_req_fn fn;
} prod_cons_async_req_s;

/**
 * Allocates a producer-consumer buffer.
 * nb_items MUST be a power 2.
 */
prod_cons_s* prod_cons_init(int nb_item);

/**
 * Teardown the producer-consumer buffer.
 */
void prod_cons_destroy(prod_cons_s*);

/**
 * Adds the item pointer to the consumer-producer buffer.
 *
 * Blocks if buffer is full, returns the position in the buffer.
 * IMPORTANT: item CANNOT be NULL!
 */
long prod_cons_produce(prod_cons_s*, void *item);

/**
 * Removes the last item pointer from the consumer-producer buffer.
 *
 * Blocks if buffer is empty, returns the position in the buffer.
 */
long prod_cons_consume(prod_cons_s*, void **item);

int prod_cons_count_items(prod_cons_s*);
int prod_cons_is_full(prod_cons_s*);
int prod_cons_is_empty(prod_cons_s*);

int prod_cons_start_thread();
int prod_cons_join_threads();
void prod_cons_async_request(prod_cons_async_req_s req, int idx);

// loops the buffer and execute functions that it finds there
int prod_cons_init_main_thread();
void* prod_cons_main_thread(void*);
void prod_cons_stop_all_threads();
void prod_cons_destroy_all_threads();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CP_H_GUARD */
