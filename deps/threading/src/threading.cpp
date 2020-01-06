#include "prod-cons.h"
#include "threading.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <thread>
#include <map>
#include <list>
#include <mutex>

#include "util.h"

using namespace std;

typedef struct thr_info_ {
  int tid;
  int nbThreads;
  void *args;
  threading_callback fn;
} thr_info_s;

static pthread_t *async_thread = nullptr, *threads = nullptr, timer_thread;
static int nbAsyncThrs = 0, allocedAsyncThrs = 0;
static thr_info_s *info_thrs = nullptr;
static int nbThrsExec = 0, isStarted = 0;
static thread_local threading_id myThreadID;

static mutex timer_lock;
static map<uint64_t, pair<threading_timer_callback, void*>> timer_fns;

static void *thrClbk(void *args);
static void *timerClbk(void *args);
static int msleep(uint64_t msec);

int prod_cons_start_thread()
{
  intptr_t pdIdx = prod_cons_init_main_thread();
  if (pdIdx != -1) {
    if (async_thread == NULL) {
      malloc_or_die(async_thread, 8);
      allocedAsyncThrs = 8;
    } else if (allocedAsyncThrs < nbAsyncThrs) {
      realloc_or_die(async_thread, allocedAsyncThrs+8);
      allocedAsyncThrs += 8;
    }
    thread_create_or_die(&(async_thread[nbAsyncThrs]), NULL,
      prod_cons_main_thread, (void*)pdIdx);
    nbAsyncThrs++; // not thread-safe
  }
  return pdIdx;
}

int prod_cons_join_threads()
{
  prod_cons_stop_all_threads();
  for (int i = 0; i < nbAsyncThrs; ++i) {
    thread_join_or_die(async_thread[i], NULL);
  }
  prod_cons_destroy_all_threads();
  nbAsyncThrs = 0;
  return 0;
}

void threading_start(int nbThreads, int asyncs, threading_callback callback, void *args)
{
  if (isStarted) return;
  isStarted = 1;
  nbThrsExec = nbThreads;
  // malloc_or_die(async_thread, asyncs); // done in prod_cons_start_thread()
  malloc_or_die(threads, nbThreads);
  malloc_or_die(info_thrs, nbThreads);

  for (int i = 0; i < nbThreads; ++i) {
    info_thrs[i].tid = i;
    info_thrs[i].nbThreads = nbThreads;
    info_thrs[i].args = args;
    info_thrs[i].fn = callback;
    thread_create_or_die(&(threads[i]), NULL, thrClbk, &(info_thrs[i]));
  }

  for (int i = 0; i < asyncs; ++i) {
    int pcIdx = prod_cons_start_thread();
    if (pcIdx == -1) {
      fprintf(stderr, "Could not launch all the requested asyncs\n");
      exit(EXIT_FAILURE);
    }
  }

  // timer
  thread_create_or_die(&timer_thread, NULL, timerClbk, NULL);
}

void threading_join()
{
  for (int i = 0; i < nbThrsExec; ++i) {
    thread_join_or_die(threads[i], NULL);
  }
  prod_cons_join_threads();
  free(threads);
  free(info_thrs);
  free(async_thread);
  async_thread = nullptr;
  allocedAsyncThrs = 0;
  isStarted = 0;
}

int threading_async(int idAsync, prod_cons_req_fn fn, void *args)
{
  prod_cons_async_request((prod_cons_async_req_s){
    .args = args,
    .fn = fn
  }, idAsync);
  return 0;
}

int threading_getMaximumHardwareThreads()
{
  return std::thread::hardware_concurrency(); // C++11
}

void threading_pinThisThread(int coreID)
{
#ifdef __linux__
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(coreID, &cpu_set);
  sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
#endif /* __linux__ */
}

int threading_getNbThreads()
{
  return nbThrsExec;
}

threading_id threading_getMyThreadID()
{
  return myThreadID;
}

int threading_timer(int millis, threading_timer_callback fn, void *arg)
{
  struct timespec now;
  uint64_t now_ms;

  if (millis < 0) return -1;

  clock_gettime(CLOCK_MONOTONIC_RAW, &now);
  now_ms = now.tv_sec * 1000 + now.tv_nsec / 1000000;
  now_ms += millis;
  timer_lock.lock();
  timer_fns.insert(make_pair(now_ms, make_pair(fn, arg)));
  timer_lock.unlock();

  return 0;
}

static void *thrClbk(void *args)
{
  thr_info_s *info = (thr_info_s*)args;
  myThreadID = info->tid;
  info->fn(info->tid, info->nbThreads, info->args);
  return NULL;
}

static void *timerClbk(void *args)
{
  // clock_getres(CLOCK_MONOTONIC_RAW, &timer_resolution); // TODO: check resolution
  // CLOCKS_PER_SEC
  struct timespec now;
  uint64_t now_ms;

  while (isStarted)
  {
    map<threading_timer_callback, void*> fns;
    list<uint64_t> toErase;

    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    now_ms = now.tv_sec * 1000 + now.tv_nsec / 1000000;

    timer_lock.lock();
    for (auto it = timer_fns.begin(); it != timer_fns.end(); ++it) {
      // stuff waiting on the timer
      if (it->first < now_ms) {
        auto fn = it->second.first;
        auto arg = it->second.second;
        toErase.push_back(it->first);
        fns.insert(make_pair(fn, arg));
      } else {
        break; // assumes ordered map
      }
    }
    for (auto it = toErase.begin(); it != toErase.end(); ++it) {
      timer_fns.erase(*it);
    }
    timer_lock.unlock();

    for (auto it = fns.begin(); it != fns.end(); ++it) {
      auto fn = it->first;
      auto arg = it->second;
      fn(arg); // executes the timer function
    }
    //do stuff
    msleep(1);
  }
  return NULL;
}

static int msleep(uint64_t msec)
{
  struct timespec ts;
  int res;

  ts.tv_sec = msec / 1000;
  ts.tv_nsec = (msec % 1000) * 1000000;

  do {
    res = nanosleep(&ts, &ts);
  } while (res && errno == EINTR);

  return res;
}
