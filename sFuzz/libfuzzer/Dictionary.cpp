#include <set>
#include "Dictionary.h"

using namespace std;
using namespace eth;

namespace fuzzer {
  void Dictionary::fromAddress(bytes data) {
    ExtraData d;
    d.data = data;
    extras.push_back(d);
  }
  
  void Dictionary::fromCode(bytes code) {
    int pc = 0;
    int size = code.size();
    struct bytesComparation {
      bool operator ()(const bytes a, const bytes b) {
        if (a.size() == b.size()) return memcmp(b.data(), a.data(), a.size()) > 0;
        return b.size() > a.size();
      }
    };
    set<bytes, bytesComparation> values;
    while (pc < size) {
      if (code[pc] > 0x5f && code[pc] < 0x80) {
        /* PUSH instruction */
        int jumpNum = code[pc] - 0x5f;
        // 检查 jumpNum 是否超出边界
        if (pc + 1 + jumpNum <= size) {
          bytes value = bytes(code.begin() + pc + 1, code.begin() + pc + 1 + jumpNum);
          values.insert(value);
          pc += jumpNum;
        } else {
          // 如果越界，可以选择记录警告，或直接退出循环
          break; // 或者 continue;
        }
      }
      pc += 1;
    }
    for (auto value : values) {
      ExtraData d;
      d.data = value;
      extras.push_back(d);
    }
  }

}
