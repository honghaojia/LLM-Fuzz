#include "TargetExecutive.h"
#include "Logger.h"
#include <libethcore/LogEntry.h>
#include <sstream>  

namespace fuzzer {
  void TargetExecutive::deploy(bytes data, OnOpFunc onOp) {
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
  }

  TargetContainerResult TargetExecutive::exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<bytes> outputs;
    size_t savepoint = program->savepoint();
    
     // 字符串日志
    std::ostringstream logStream;  // 用于构建日志内容
    
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const* ext) {
      auto vm = dynamic_cast<LegacyVM const*>(_vm);
      /* Oracle analyze data */
      switch (inst) {
        case Instruction::CALL:
        case Instruction::CALLCODE:
        case Instruction::DELEGATECALL:
        case Instruction::STATICCALL: {
          vector<u256>::size_type stackSize = vm->stack().size();
          u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
          auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
          auto inOff = (uint64_t) vm->stack()[sizeOffset];
          auto inSize = (uint64_t) vm->stack()[sizeOffset - 1];
          auto first = vm->memory().begin();
          OpcodePayload payload;
          payload.caller = ext->myAddress;
          payload.callee = Address((u160)vm->stack()[stackSize - 2]);
          payload.pc = pc;
          payload.gas = vm->stack()[stackSize - 1];
          payload.wei = wei;
          payload.inst = inst;
          payload.data = bytes(first + inOff, first + inOff + inSize);
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
          break;
        }
        case Instruction::SSTORE: {
            OpcodePayload payload;
            payload.pc = pc;
            payload.inst = inst;
            payload.isSstore = true;

            vector<u256>::size_type stackSize = vm->stack().size();
            if (stackSize >= 2) {
                payload.sstoreKey = vm->stack()[stackSize - 1];
                payload.sstoreValue = vm->stack()[stackSize - 2];
            }
            oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            break;
        }
        case Instruction::SUICIDE: {
          OpcodePayload payload;
          payload.pc = pc;
          payload.inst = inst;
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
          break;
        }
        
        default: {
            OpcodePayload payload;
            payload.pc = pc;
            payload.inst = inst;
            if (
                inst == Instruction::CALLER ||
                inst == Instruction::ORIGIN ||
                inst == Instruction::CALLDATALOAD||
                inst == Instruction::SUICIDE ||
                inst == Instruction::NUMBER ||
                inst == Instruction::TIMESTAMP ||
                inst == Instruction::INVALID ||
                inst == Instruction::ADD ||
                inst == Instruction::SUB ||
                inst == Instruction::MUL ||
                inst == Instruction::DIV
                ) {
                vector<u256>::size_type stackSize = vm->stack().size();
                if (inst == Instruction::ADD || inst == Instruction::SUB || inst == Instruction::MUL || inst == Instruction::DIV) {
                    if (stackSize >= 2) {
                        auto left = vm->stack()[stackSize - 1];
                        auto right = vm->stack()[stackSize - 2];
                        if (inst == Instruction::ADD) {
                            auto total256 = left + right;
                            auto total512 = (u512) left + (u512) right;
                            payload.isOverflow = total512 != total256;
                        } else if (inst == Instruction::SUB) {
                            payload.isUnderflow = left < right;
                        } else if (inst == Instruction::MUL) {
                            auto total256 = left * right;
                            auto total512 = (u512) left * (u512) right;
                            payload.isOverflow = total512 != total256;
                        } else if (inst == Instruction::DIV) {
                            payload.isDivideByZero = right == 0;
                        }
                    }
                }
                oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            }
            break;
          }
      }
      /* Mutation analyzes data */
      switch (inst) {
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ: {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (stackSize >= 2) {
            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            /* calculate if command inside a function */
            u256 temp = left > right ? left - right : right - left;
            lastCompValue = temp + 1;
          }
          break;
        }
        default: { break; }
      }
      /* Calculate left and right branches for valid jumpis*/
      auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
      if (inst == Instruction::JUMPCI && recordable) {
        jumpDest1 = (u64) vm->stack().back();
        jumpDest2 = pc + 1;
      }
      /* Calculate actual jumpdest and add reverse branch to predicate */
      recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
      if (prevInst == Instruction::JUMPCI && recordable) {
        auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
        tracebits.insert(branchId);
        
        //std::cout << "found new trace:" << branchId << std::endl;
        
        /* Calculate branch distance */
        u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
        branchId = to_string(recordParam.lastpc) + ":" + to_string(jumpDest);
        predicates[branchId] = lastCompValue;
      }
      prevInst = inst;
      recordParam.lastpc = pc;
    };
    /* Decode and call functions */
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    if (res.excepted != TransactionException::None) {
      auto exceptionId = to_string(recordParam.lastpc);
      uniqExceptions.insert(exceptionId) ;
      /* Save Call Log */
      OpcodePayload payload;
      payload.inst = Instruction::INVALID;
      oracleFactory->save(OpcodeContext(0, payload));
    }
    oracleFactory->finalize();
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx ++ ) {
      /* Update payload */
      auto func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      /* Ignore JUMPI until program reaches inside function */
      recordParam.isDeployment = false;
      OpcodePayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      oracleFactory->save(OpcodeContext(0, payload));
      res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      
      // 处理日志
      LogEntries logs = res.logs;
      bool eventTriggered = false;  // Flag to indicate if an event was triggered
      
      logStream << "In function `" << fd.name << "`, ";

      if (!logs.empty()) {
        eventTriggered = true;  // Events were triggered

        logStream << "the following events were triggered: ";
        for (const LogEntry& log : logs) {
          if (!log.topics.empty()) {
            // Event hash
            auto eventHash = log.topics[0].hex();
            
            // Find event signature in the eventHashToSignatureMap
            auto it = ca.eventHashToSignatureMap.find(eventHash);
            if (it != ca.eventHashToSignatureMap.end()) {
              logStream << "Event: `" << it->second << "`; ";

              // Process indexed parameters
              if (log.topics.size() > 1) {
                logStream << "Indexed Parameters: ";
                for (size_t i = 1; i < log.topics.size(); ++i) {
                  logStream << "Param" << i << ": " << log.topics[i].hex() << "; ";
                }
              }

              // Process non-indexed parameters (log.data)
              if (!log.data.empty()) {
                logStream << "Non-Indexed Parameters: " << toHex(log.data) << "; ";
              }
            } else {
              logStream << "Unknown Event with Hash: " << eventHash << "; ";
            }
          }
        }
      } else {
        // If no events were triggered
        logStream << "No events were triggered during this transaction; ";
      }
      
      string exception;

      // 处理异常信息
      switch (res.excepted) {
        case TransactionException::None: exception = "No exception"; break;
    		case TransactionException::BadRLP: exception = "BadRLP"; break;
    		case TransactionException::InvalidFormat: exception = "InvalidFormat"; break;
    		case TransactionException::OutOfGasIntrinsic: exception = "OutOfGasIntrinsic"; break;
    		case TransactionException::InvalidSignature: exception = "InvalidSignature"; break;
    		case TransactionException::InvalidNonce: exception = "InvalidNonce"; break;
    		case TransactionException::NotEnoughCash: exception = "NotEnoughCash"; break;
    		case TransactionException::OutOfGasBase: exception = "OutOfGasBase"; break;
    		case TransactionException::BlockGasLimitReached: exception = "BlockGasLimitReached"; break;
    		case TransactionException::BadInstruction: exception = "BadInstruction"; break;
    		case TransactionException::BadJumpDestination: exception = "BadJumpDestination"; break;
    		case TransactionException::OutOfGas: exception = "OutOfGas"; break;
    		case TransactionException::OutOfStack: exception = "OutOfStack"; break;
    		case TransactionException::StackUnderflow: exception = "StackUnderflow"; break;
        // 可根据需要添加其他异常类型
        default: exception = "Unknown"; break;
      }
      
      logStream << "Exception: " << exception << ".";  // 追加异常到日志
      
      Logger::info("TransactionException:" + exception);
        
      outputs.push_back(res.output);
      if (res.excepted != TransactionException::None) {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
      }
      oracleFactory->finalize();
    }
    /* Reset data before running new contract */
    program->rollback(savepoint);
    string cksum = "";
    for (auto t : tracebits) cksum = cksum + t;
    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum,logStream.str());
  }
}
