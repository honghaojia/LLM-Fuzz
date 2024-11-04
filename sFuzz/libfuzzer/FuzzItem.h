#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    bytes data;  // std::vector<unsigned char>
    TargetContainerResult res;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;

    // 默认构造函数
    FuzzItem() = default;

    // 带参数的构造函数
    FuzzItem(const bytes& _data) : data(_data) {}

    // 拷贝构造函数
    FuzzItem(const FuzzItem& other) 
      : data(other.data), res(other.res), fuzzedCount(other.fuzzedCount), depth(other.depth) {}

    // 拷贝赋值运算符
    FuzzItem& operator=(const FuzzItem& other) {
      if (this != &other) {
        data = other.data;
        res = other.res;
        fuzzedCount = other.fuzzedCount;
        depth = other.depth;
      }
      return *this;
    }
  };

  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
