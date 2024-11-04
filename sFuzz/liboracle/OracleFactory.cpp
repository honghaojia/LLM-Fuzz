#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize() {
  function.clear();
}

void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

vector<bool> OracleFactory::analyze() {
  const uint8_t total = 11;
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(false);
  }

  for (const auto& func : functions) {
    vulnerabilities[0] = vulnerabilities[0] || detectGaslessSend(func);
    vulnerabilities[1] = vulnerabilities[1] || detectExceptionDisorder(func);
    vulnerabilities[2] = vulnerabilities[2] || detectTimeDependency(func);
    vulnerabilities[3] = vulnerabilities[3] || detectNumberDependency(func);
    vulnerabilities[4] = vulnerabilities[4] || detectDelegateCall(func);
    vulnerabilities[5] = vulnerabilities[5] || detectReentrancy(func);
    vulnerabilities[6] = vulnerabilities[6] || detectFreezing(func);
    vulnerabilities[7] = vulnerabilities[7] || detectUnderflow(func);
    vulnerabilities[8] = vulnerabilities[8] || detectOverflow(func);
    vulnerabilities[9] = vulnerabilities[9] || detectEtherLeakage(func);
    vulnerabilities[10] = vulnerabilities[10] || detectSelfdestruct(func);
  }

  functions.clear();
  return vulnerabilities;
}

// 以下是每个漏洞检测的具体实现

bool OracleFactory::detectGaslessSend(const vector<OpcodeContext>& func) {
  for (const auto& ctx : func) {
    auto level = ctx.level;
    auto inst = ctx.payload.inst;
    auto gas = ctx.payload.gas;
    auto data = ctx.payload.data;
    if (level == 1 && inst == Instruction::CALL && data.empty() && (gas == 2300 || gas == 0)) {
      return true;
    }
  }
  return false;
}

bool OracleFactory::detectExceptionDisorder(const vector<OpcodeContext>& func) {
  if (func.empty()) return false;
  auto rootCallResponse = func.back();
  bool rootException = isExceptionInstruction(rootCallResponse.payload.inst) && rootCallResponse.level == 0;

  for (const auto& ctx : func) {
    if (!rootException && isExceptionInstruction(ctx.payload.inst) && ctx.level > 0) {
      return true;
    }
  }
  return false;
}

bool OracleFactory::isExceptionInstruction(dev::eth::Instruction inst) {
  return inst == Instruction::INVALID || inst == Instruction::REVERT;
}

bool OracleFactory::detectTimeDependency(const vector<OpcodeContext>& func) {
  bool has_transfer = false;
  bool has_timestamp = false;
  for (const auto& ctx : func) {
    has_transfer |= ctx.payload.wei > 0;
    has_timestamp |= ctx.payload.inst == Instruction::TIMESTAMP;
  }
  return has_transfer && has_timestamp;
}

bool OracleFactory::detectNumberDependency(const vector<OpcodeContext>& func) {
  bool has_transfer = false;
  bool has_number = false;
  for (const auto& ctx : func) {
    has_transfer |= ctx.payload.wei > 0;
    has_number |= ctx.payload.inst == Instruction::NUMBER;
  }
  return has_transfer && has_number;
}

bool OracleFactory::detectDelegateCall(const vector<OpcodeContext>& func) {
  if (func.empty()) return false;
  auto rootCall = func.front();
  auto data = rootCall.payload.data;
  auto caller = rootCall.payload.caller;
  for (const auto& ctx : func) {
    if (ctx.payload.inst == Instruction::DELEGATECALL) {
      if (data == ctx.payload.data ||
          caller == ctx.payload.callee ||
          toHex(data).find(toHex(ctx.payload.callee)) != string::npos) {
        return true;
      }
    }
  }
  return false;
}

bool OracleFactory::detectReentrancy(const vector<OpcodeContext>& func) {
    for (size_t i = 0; i < func.size(); ++i) {
        const auto& ctx = func[i];
        if (ctx.payload.inst == Instruction::CALL && ctx.level > 0 && ctx.payload.wei > 0) {
            // 检查 gas 量
            if (ctx.payload.gas > 2300) {
                // 检查在外部调用之前，是否有状态变化（SSTORE）
                bool stateChangeBeforeCall = false;
                for (size_t j = 0; j < i; ++j) {
                    const auto& priorCtx = func[j];
                    if (priorCtx.payload.isSstore) {
                        stateChangeBeforeCall = true;
                        break;
                    }
                }
                if (stateChangeBeforeCall) {
                    return true;
                }
            }
        }
    }
    return false;
}




bool OracleFactory::detectFreezing(const vector<OpcodeContext>& func) {
  bool has_delegate = false;
  bool has_transfer = false;
  for (const auto& ctx : func) {
    has_delegate |= ctx.payload.inst == Instruction::DELEGATECALL;
    has_transfer |= (ctx.level == 1 && (
                      ctx.payload.inst == Instruction::CALL ||
                      ctx.payload.inst == Instruction::CALLCODE ||
                      ctx.payload.inst == Instruction::SUICIDE));
  }
  return has_delegate && !has_transfer;
}

bool OracleFactory::detectUnderflow(const vector<OpcodeContext>& func) {
  for (const auto& ctx : func) {
    if (ctx.payload.isUnderflow) {
      return true;
    }
  }
  return false;
}

bool OracleFactory::detectOverflow(const vector<OpcodeContext>& func) {
  for (const auto& ctx : func) {
    if (ctx.payload.isOverflow) {
      return true;
    }
  }
  return false;
}

bool OracleFactory::detectEtherLeakage(const vector<OpcodeContext>& func) {
  bool hasUnprotectedTransfer = false;
  bool functionHasTransfer = false;
  bool functionHasAuth = false;

  for (const auto& ctx : func) {
    auto inst = ctx.payload.inst;

    // 检查是否有以太币转移
    if ((inst == Instruction::CALL || inst == Instruction::CALLCODE || inst == Instruction::DELEGATECALL || inst == Instruction::STATICCALL)
        && ctx.payload.wei > 0) {
      functionHasTransfer = true;
    }

    // 简单判断是否存在访问控制（示例）
    if (inst == Instruction::CALLER || inst == Instruction::ORIGIN || inst == Instruction::CALLDATALOAD) {
      functionHasAuth = true;
    }
  }

  // 如果函数有以太币转移且没有访问控制，则认为存在以太币泄露风险
  hasUnprotectedTransfer = functionHasTransfer && !functionHasAuth;

  return hasUnprotectedTransfer;
}

bool OracleFactory::detectSelfdestruct(const vector<OpcodeContext>& func) {
  bool hasSelfdestruct = false;
  bool functionHasAuth = false;

  for (const auto& ctx : func) {
    auto inst = ctx.payload.inst;

    // 检查是否有 SUICIDE 指令
    if (inst == Instruction::SUICIDE) {
      hasSelfdestruct = true;
    }

    // 简单判断是否存在访问控制（示例）
    if (inst == Instruction::CALLER || inst == Instruction::ORIGIN || inst == Instruction::CALLDATALOAD) {
      functionHasAuth = true;
    }
  }

  // 如果函数有自毁操作且没有访问控制，则认为存在自毁漏洞
  return hasSelfdestruct && !functionHasAuth;
}
