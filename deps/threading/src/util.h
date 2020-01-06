#ifndef UTIL_H_GUARD
#define UTIL_H_GUARD

#if defined(__APPLE__)
#include <semaphore.h>

//#define thr_sem_t           sem_t*
typedef sem_t* thr_sem_t;
#define thr_sem_init(s, n)  s = sem_open("thrSem", O_CREAT | O_EXCL, \
                            S_IRUSR | S_IWUSR, n); if (s != SEM_FAILED) { \
                            sem_unlink("thrSem"); }
#define thr_sem_destroy(s)  sem_close(s)
#define thr_sem_post(s)     sem_post(s)
#define thr_sem_wait(s)     sem_wait(s)

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach_init.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <pthread.h>

// mac os also need to re-implement some functions
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"

typedef struct cpu_set {
  uint32_t    count;
} cpu_set_t;

static inline void
CPU_ZERO(cpu_set_t *cs) { cs->count = 0; }

static inline void
CPU_SET(int num, cpu_set_t *cs) { cs->count |= (1 << num); }

static inline int
CPU_ISSET(int num, cpu_set_t *cs) { return (cs->count & (1 << num)); }

static inline int
sched_getaffinity(pid_t pid, size_t cpu_size, cpu_set_t *cpu_set)
{
  int32_t core_count = 0;
  size_t  len = sizeof(core_count);
  int ret = sysctlbyname(SYSCTL_CORE_COUNT, &core_count, &len, 0, 0);
  if (ret) {
    printf("error while get core count %d\n", ret);
    return -1;
  }
  cpu_set->count = 0;
  for (int i = 0; i < core_count; i++) {
    cpu_set->count |= (1 << i);
  }

  return 0;
}

static inline int
pthread_setaffinity_np(
  pthread_t thread, size_t cpu_size, cpu_set_t *cpu_set
) {
  thread_port_t mach_thread;
  int core = 0;

  for (core = 0; core < 8 * cpu_size; core++) {
    if (CPU_ISSET(core, cpu_set)) break;
  }
  printf("binding to core %d\n", core);
  thread_affinity_policy_data_t policy = { core };
  mach_thread = pthread_mach_thread_np(thread);
  thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
                    (thread_policy_t)&policy, 1);
  return 0;
}

#define sched_setaffinity pthread_setaffinity_np

#elif defined(__linux__)
#include <semaphore.h>
#include <pthread.h>
#include <sched.h>

#define thr_sem_t           sem_t
#define thr_sem_init(s, n)  sem_init(&s, 0, n)
#define thr_sem_destroy(s)  sem_destroy(&s)
#define thr_sem_post(s)     sem_post(&s)
#define thr_sem_wait(s)     sem_wait(&s)

#else  /* !__APPLE__ && !__linux__ */
// TODO: other arches
#endif /* __APPLE__ */

#define malloc_or_die(var, nb) \
if (((var) = (__typeof__((var)))malloc((nb) * sizeof(__typeof__(*(var))))) == NULL) { \
  fprintf(stderr, "malloc error \"%s\" at " __FILE__":%i\n", \
  strerror(errno), __LINE__); \
  exit(EXIT_FAILURE); \
} \
// malloc_or_die

#define realloc_or_die(var, nb) \
if (((var) = (__typeof__((var)))realloc((var), (nb) * sizeof(__typeof__(*(var))))) == NULL) { \
  fprintf(stderr, "realloc error \"%s\" at " __FILE__":%i\n", \
  strerror(errno), __LINE__); \
  exit(EXIT_FAILURE); \
} \
// malloc_or_die

#if defined(__linux__) || defined(__APPLE__)
#define thread_create_or_die(thr, attr, callback, arg) \
  if (pthread_create(thr, attr, callback, (void *)(arg)) != 0) { \
    fprintf(stderr, "Error creating thread at " __FILE__ ":%i\n", __LINE__); \
    exit(EXIT_FAILURE); \
  } \
// thread_create_or_die

#define thread_join_or_die(thr, res) \
  if (pthread_join(thr, res)) { \
    fprintf(stderr, "Error joining thread at " __FILE__ ":%i\n", __LINE__); \
    exit(EXIT_FAILURE); \
  } \
// thread_join_or_die
#else /* !defined(__linux__) && !defined(__APPLE__) */
#define thread_create_or_die(thr, attr, callback, arg) /* empty */
#define thread_join_or_die(thr, res)                   /* empty */
#endif /* defined(__linux__) || defined(__APPLE__) */

#endif /* UTIL_H_GUARD */
