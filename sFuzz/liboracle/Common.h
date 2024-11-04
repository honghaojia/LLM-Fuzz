#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

const uint8_t GASLESS_SEND = 0;
const uint8_t EXCEPTION_DISORDER = 1;
const uint8_t TIME_DEPENDENCY = 2;
const uint8_t NUMBER_DEPENDENCY = 3;
const uint8_t DELEGATE_CALL = 4;
const uint8_t REENTRANCY = 5;
const uint8_t FREEZING = 6;
const uint8_t OVERFLOW = 7;
const uint8_t UNDERFLOW = 8;
const uint8_t ETHER_LEAKAGE = 9;
const uint8_t SELFDESTRUCT = 10;

struct OpcodePayload {
  u256 wei = 0;
  u256 gas = 0;
  u256 pc = 0;
  Instruction inst;
  bytes data;
  Address caller;
  Address callee;
  bool isOverflow = false;
  bool isUnderflow = false;
  bool isDivideByZero = false;
  
  // 新增成员变量
  bool isSstore = false;    // 标记是否为SSTORE指令
  u256 sstoreKey = 0;       // SSTORE指令的键
  u256 sstoreValue = 0;     // SSTORE指令的值
};

struct OpcodeContext {
  u256 level;
  OpcodePayload payload;
  OpcodeContext(u256 _level, OpcodePayload _payload): level(_level), payload(_payload) {}
};

using SingleFunction = vector<OpcodeContext>;
using MultipleFunction = vector<SingleFunction>;
