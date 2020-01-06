#ifndef HANDLE_ERROR_H_GUARD_
#define HANDLE_ERROR_H_GUARD_

#include <stdio.h>

#define TSL_ADD_ERROR(...) \
  sprintf(tsl_last_error_msg, __VA_ARGS__) \
\
//

extern __thread char tsl_last_error_msg[1024];

#endif /* HANDLE_ERROR_H_GUARD_ */