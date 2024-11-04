#pragma once
#include <vector>
#include "Common.h"
#include "Util.h"

using namespace std;
using namespace dev;

namespace fuzzer {
  /*
  * Read push data inside bytecode to from dictionary
  * Pad left and right to enough 32 bytes
  */
  class Dictionary {
    public:
      vector<ExtraData> extras;
      void fromCode(bytes code);
      void fromAddress(bytes address);
      
      struct ContractFunction {
          std::string functionName; // ������
          std::map<std::string, std::string> parameters; // �������Ͷ������ֵ�ļ�ֵ��
      };
  };
}
