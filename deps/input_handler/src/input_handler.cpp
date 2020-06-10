#include "input_handler.h"

#include <stdio.h>
#include <string>
#include <cstring>
#include <map>
#include <vector>
#include <sstream>
#include <iostream>
#include <errno.h>

using namespace std;

static map<string, string> inputArgs;

template <typename T>
inline T convert_arg(string &arg);

void input_parse(int argc, char **argv)
{
  for (int i = 1; i < argc; ++i) {
    string arg(argv[i]);
		string delimiter("=");
		size_t posDelimiter = arg.find(delimiter);
		string token = arg.substr(0, posDelimiter);
		string val("");

		if (posDelimiter == string::npos) {
      // this one is not in the format <param>=<val>
      inputArgs[arg] = "";
      continue;
		}

    val = arg.substr(posDelimiter+1, arg.length());
		inputArgs[token] = val;
  }
}

size_t split(const string &txt, vector<string> &strs, char ch)
{
  size_t pos = txt.find( ch );
  size_t initialPos = 0;
  strs.clear();

  // Decompose statement
  while (pos != string::npos) {
    string target = txt.substr(initialPos, pos - initialPos);
    if (target.length() > 1) { // at least an '=' is needed
      strs.push_back(target);
    }
    initialPos = pos + 1;
    pos = txt.find( ch, initialPos );
  }

  // Add the last one
  strs.push_back( txt.substr( initialPos, std::min( pos, txt.size() ) - initialPos + 1 ) );

  return strs.size();
}

void input_parse_file(char *fileName)
{
  FILE *fp = fopen(fileName, "r");
  size_t fileSize;
  void *readFile;
  vector<string> input;

  if (fp == NULL) {
    fprintf(stderr, "Problem with the input file: %s\n", strerror(errno));
    return;
  }

  fseek(fp, 0, SEEK_END);
  fileSize = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  readFile = malloc(fileSize);

  fread(readFile, 1, fileSize, fp);
  split(string((char*)readFile), input, ' ');

  for (auto it = input.begin(); it != input.end(); ++it) {
    string arg(*it);
		string delimiter("=");
		size_t posDelimiter = arg.find(delimiter);
		string token = arg.substr(0, posDelimiter);
		string val("");

		if (posDelimiter == string::npos) {
      // this one is not in the format <param>=<val>
      inputArgs[arg] = "";
      continue;
		}

    val = arg.substr(posDelimiter+1, arg.length());
		inputArgs[token] = val;
  }
}

long input_getLong(char *arg)
{
  string token(arg);
  auto it = inputArgs.find(token);
  if (it == inputArgs.end()) {
    return -1;
  }
  long res = convert_arg<long>(it->second);
  return res;
}

double input_getDouble(char *arg)
{
  string token(arg);
  auto it = inputArgs.find(token);
  if (it == inputArgs.end()) {
    return -1.0;
  }
  double res = convert_arg<double>(it->second);
  return res;
}

size_t input_getString(char *arg, char *out)
{
  string token(arg);
  auto it = inputArgs.find(token);
  if (it == inputArgs.end() || out == NULL) {
    return -1;
  }
  const char *val = it->second.c_str();
  size_t i = 0;
  do {
    out[i] = val[i];
  } while (val[i++] != '\0');
  return i;
}

int input_exists(char *arg)
{
  string token(arg);
  auto it = inputArgs.find(token);
  return it != inputArgs.end();
}

int input_foreach(int(*fn)(const char*))
{
  for (auto it = inputArgs.begin(); it != inputArgs.end(); ++it) {
    int res = fn(it->first.c_str());
    if (res != 0) return res;
  }
  return 0;
}

template <typename T>
inline T convert_arg(string &arg)
{
  if (!arg.empty()) {
    T ret;
    istringstream iss(arg);
    if (arg.find("0x") == 0) {
      iss >> hex >> ret;
    } else if (arg.find("0b") == 0) {
      ret = (T)stoll(arg.substr(2, arg.length()), nullptr, 2);
    } else if (arg.find("0") == 0) {
      iss >> oct >> ret;
    } else {
      iss >> dec >> ret;
    }

    if (iss.fail()) {
      cout << "Convert error: cannot convert string '" << arg << "' to value" << endl;
      return T();
    }
    return ret;
  }
  return T();
}
