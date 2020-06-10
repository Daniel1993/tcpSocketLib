#ifndef INPUT_HANDLER_H_GUARD
#define INPUT_HANDLER_H_GUARD

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

  void input_parse(int argc, char **argv);
  void input_parse_file(char *fileName); // the same format as in the command line
  long input_getLong(char *arg);
  double input_getDouble(char *arg);
  size_t input_getString(char *arg, char *out);
  int input_exists(char *arg);

  // loops all inputs, return !=0 to stop
  int input_foreach(int(*fn)(const char*));

#ifdef __cplusplus
}
#endif

#endif /* INPUT_HANDLER_H_GUARD */
