#pragma once
#include<iostream>
#include <fstream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;
namespace fuzzer {
  class Logger {
    public:
      static bool enabled;
      static ofstream debugFile;
      static ofstream infoFile;
      static void setEnabled(bool _enabled);
      static void info(string str);
      static void debug(string str);
      static void clearLogs();
      static string testFormat(bytes data);
  };
}
