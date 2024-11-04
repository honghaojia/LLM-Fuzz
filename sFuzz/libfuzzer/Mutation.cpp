#include <ctime>
#include "Mutation.h"
#include "Dictionary.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Logger.h"
#include <chrono>
#include <iostream>


using namespace std;
using namespace fuzzer;

uint64_t Mutation::stageCycles[32] = {};

Mutation::Mutation(FuzzItem item, Dicts dicts, TargetExecutive& executive,std::string contractName)
    : curFuzzItem(item), dicts(dicts), dataSize(item.data.size()), executive(executive),contractName(contractName) {
    
    effCount = 0;
    eff = bytes(effALen(dataSize), 0);
    eff[0] = 1;
    if (effAPos(dataSize - 1) != 0) {
        eff[effAPos(dataSize - 1)] = 1;
        effCount++;
    }
    stageName = "init";

    // 调用初始化函数来初始化 mutateInfo
    initMutateInfo();
}

void Mutation::initMutateInfo() {
    // 遍历当前合约的函数定义，并初始化所有参数为需要变异
    for (auto& fd : executive.ca.fds) {  // 通过 executive.ca.fds 获取函数定义
        std::unordered_map<std::string, std::string> paramMap;

        // 遍历函数参数，默认所有参数都需要变异
        for (auto& td : fd.tds) {
            paramMap[td.paraname] = "yes";  // 默认所有参数都需要变异
        }

        // 将参数变异信息存入 mutateInfo
        mutateInfo[fd.name] = paramMap;
    }
}


// 填充所有函数的参数位置
void Mutation::populateParamPositions() {
    size_t position = 32 + 32; // 跳过 sender 和 block

    auto consultRealLen = [&]() {
        // 模拟获取随机的长度（根据实际情况调整）
        int len = curFuzzItem.data[position];
        position += 32; // 动态参数的长度字段占 32 bytes
        return len;
    };

    auto consultContainerLen = [](int realLen) {
        return (realLen % 32 == 0) ? realLen : ((realLen / 32 + 1) * 32);
    };

    // 遍历 executive.ca.fds，计算每个函数的参数位置
    for (const auto& fd : executive.ca.fds) {
        std::unordered_map<std::string, ParamPosition> paramPositions;

        // 遍历函数定义的参数，并计算每个参数的起始和结束位置
        for (const auto& td : fd.tds) {
            size_t start = position;
            size_t end = 0;

            switch (td.dimensions.size()) {
                case 0: {
                    // 单一参数
                    int realLen = td.isDynamic ? consultRealLen() : 32;
                    end = start + consultContainerLen(realLen);
                    break;
                }
                case 1: {
                    // 1维数组
                    int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
                    for (int i = 0; i < numElem; ++i) {
                        int realLen = td.isDynamic ? consultRealLen() : 32;
                        position += consultContainerLen(realLen);
                    }
                    end = position;
                    break;
                }
                case 2: {
                    // 2维数组
                    int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
                    int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
                    for (int i = 0; i < numElem; ++i) {
                        for (int j = 0; j < numSubElem; ++j) {
                            int realLen = td.isDynamic ? consultRealLen() : 32;
                            position += consultContainerLen(realLen);
                        }
                    }
                    end = position;
                    break;
                }
            }

            // 记录每个参数的起始和结束位置
            paramPositions[td.paraname] = {start, end};
            position = end;
        }

        // 保存每个函数的参数位置信息
        funcPositions[fd.name] = paramPositions;
    }
}

// update current mutate strategy based on LLM
void Mutation::updateMutationStrategy(std::string& file_path) {
    std::string logs = curFuzzItem.res.log;
    auto origin = curFuzzItem.data;
    std::string data = bytesToHexString(origin);
    bool isValid = false;
    const int maxEditDistance = 2; // 设置最大编辑距离为2
    std::string remind = ""; // 初始化为空，没有提醒

    // 循环请求 LLM，直到 isValid 为 true
    while (!isValid) {
        // 从 LLM 获取反馈，并传递提醒
        std::string feedback = log_based_feedback(logs, file_path, executive.ca.executionOrder(), data, executive.ca.generateFunctionAPIs(contractName), remind);
        
        // 解析 LLM 反馈，生成函数和参数的建议
        auto llmMutateInfo = parseModelFeedback(feedback);

        // 重置 isValid 变量
        isValid = true;

        if (llmMutateInfo.empty()) {
            std::cout << "LLM feedback contains no function suggestions, marking as invalid.\n";
            remind += "LLM feedback contains no function suggestions. Please provide suggestions for all state functions and their parameters. ";
            isValid = false;
            continue; // 继续请求新的反馈
        }

        // 遍历 executive.ca.fds 中的每个函数，确保每个函数和参数都在 llmMutateInfo 中
        for (const auto& fd : executive.ca.fds) {
            std::string funcNameFromContract = fd.name;

            // 生成完整函数签名
            std::string fullFuncSignature = executive.ca.functionapi(fd.name.empty() ? contractName : fd.name, fd.tds);
            
            // 生成带有 payable 的函数签名
            std::string fullFuncSignaturePayable = fullFuncSignature + " payable";

            // 处理构造函数的情况 (fd.name == "")，LLM 反馈中的构造函数名为 contractName
            if (funcNameFromContract.empty()) {
                funcNameFromContract = contractName;
            }

            // 在 LLM 反馈中找到与合约中函数匹配的条目，匹配函数名称或完整签名
            auto llmFuncIt = std::find_if(llmMutateInfo.begin(), llmMutateInfo.end(),
                [&](const std::pair<std::string, std::unordered_map<std::string, std::string>>& funcEntry) {
                    return calculateEditDistance(funcEntry.first, funcNameFromContract) <= maxEditDistance ||
                           calculateEditDistance(funcEntry.first, fullFuncSignature) <= maxEditDistance ||
                           calculateEditDistance(funcEntry.first, fullFuncSignaturePayable) <= maxEditDistance;
                });

            if (llmFuncIt == llmMutateInfo.end()) {
                std::cout << "No matching function found in LLM feedback for function: " << funcNameFromContract << " or signature: " << fullFuncSignature << ".\n";
                remind += "Function or signature '" + funcNameFromContract + "' is missing. ";
                isValid = false;
                break; // 如果没有找到匹配的函数，直接退出当前循环，继续请求
            }

            // 遍历函数的参数
            for (const auto& td : fd.tds) {
                std::string paramNameFromContract = td.paraname;

                // 在 LLM 反馈中找到与合约中参数匹配的条目，使用编辑距离进行匹配
                auto paramIt = std::find_if(llmFuncIt->second.begin(), llmFuncIt->second.end(),
                    [&](const std::pair<std::string, std::string>& paramEntry) {
                        return calculateEditDistance(paramEntry.first, paramNameFromContract) <= maxEditDistance;
                    });

                if (paramIt != llmFuncIt->second.end()) {
                    // 判断建议是否合法 ("yes" 或 "no")
                    std::string suggestionFromLLM = paramIt->second;
                    if (suggestionFromLLM == "yes" || suggestionFromLLM == "no" ||
                        suggestionFromLLM == "Yes" || suggestionFromLLM == "No") {
                        // 更新 mutateInfo 中的参数建议
                        mutateInfo[fd.name][paramNameFromContract] = suggestionFromLLM;
                    } else {
                        std::cout << "Invalid suggestion from LLM for parameter: " 
                                  << paramNameFromContract << " in function: " << funcNameFromContract 
                                  << ". Suggestion: " << suggestionFromLLM << "\n";
                        remind += "Invalid suggestion for parameter '" + paramNameFromContract + "' in function '" + funcNameFromContract + "'. ";
                        isValid = false;
                        break;
                    }
                } else {
                    std::cout << "No matching parameter found in LLM feedback for parameter: " 
                              << paramNameFromContract << " in function: " << funcNameFromContract << ".\n";
                    remind += "Parameter '" + paramNameFromContract + "' in function '" + funcNameFromContract + "' is missing. ";
                    isValid = false;
                    break;
                }
            }

            // 如果某个函数或参数不匹配，停止处理
            if (!isValid) {
                std::cout << "Invalid feedback detected, retrying...\n";
                break;
            }
        }
    }

    // 打印最终更新后的 mutateInfo
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "Updated mutation strategy: " << std::endl;
    for (const auto& funcEntry : mutateInfo) {
        std::cout << "Function: " << (funcEntry.first.empty() ? "Constructor" : funcEntry.first) << std::endl;
        for (const auto& paramEntry : funcEntry.second) {
            std::cout << "  Parameter: " << paramEntry.first << " - Suggestion: " << paramEntry.second << std::endl;
        }
    }
    std::cout << "------------------------------------------------" << std::endl;
}













// translate LLM feedback into useful information
std::unordered_map<std::string, std::unordered_map<std::string, std::string>> Mutation::parseModelFeedback(const std::string& feedback) {
    size_t start_pos = feedback.find("{");
    size_t end_pos = std::string::npos;
    if (start_pos != std::string::npos) {
        int brace_count = 1;  
        for (size_t i = start_pos + 1; i < feedback.size(); ++i) {
            if (feedback[i] == '{') {
                ++brace_count;
            } else if (feedback[i] == '}') {
                --brace_count;
                if (brace_count == 0) {
                    end_pos = i;
                    break;
                }
            }
        }
    }

    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> mutateInfo;
    if (end_pos != std::string::npos) {
        std::string extracted_json = feedback.substr(start_pos, end_pos - start_pos + 1);
        try {
            json j = json::parse(extracted_json);

            for (auto& func : j.items()) {
                std::string funcName = func.key();
                std::unordered_map<std::string, std::string> paramMap;

                for (auto& param : func.value().items()) {
                    std::string paramName = param.key();
                    std::string mutateDecision = param.value();
                    paramMap[paramName] = mutateDecision;
                }

                mutateInfo[funcName] = paramMap;
            }
        } catch (json::parse_error& e) {
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        }
    } else {
        std::cerr << "No JSON found in the feedback." << std::endl;
    }

    return mutateInfo;
}

// Mutate bytes between start and end
void Mutation::mutateParamAtPosition(int start, int end, bool isBitFlipFirst) {
    u8* buf = curFuzzItem.data.data();

    if (isBitFlipFirst) {
        // 参考 sFuzz 中的翻转策略进行比特翻转
        for (int position = start; position < end; ++position) {
            flipbit(position * 8);  // 翻转字节的第一位
            flipbit(position * 8 + 1);  // 翻转字节的第二位
            flipbit(position * 8 + 2);  // 翻转字节的第三位
            flipbit(position * 8 + 3);  // 翻转字节的第四位
            flipbit(position * 8 + 4);  // 翻转字节的第五位
            flipbit(position * 8 + 5);  // 翻转字节的第六位
            flipbit(position * 8 + 6);  // 翻转字节的第七位
            flipbit(position * 8 + 7);  // 翻转字节的第八位

            if (position < curFuzzItem.data.size() - 1) {
                u16* buf16 = reinterpret_cast<u16*>(buf + position);
                *buf16 ^= 0xFFFF;  // 翻转16位的值

                if (position < curFuzzItem.data.size() - 3) {
                    u32* buf32 = reinterpret_cast<u32*>(buf + position);
                    *buf32 ^= 0xFFFFFFFF;  // 翻转32位的值
                }
            }
        }

        // 额外可以添加sFuzz的 `twoWalkingBit` 和 `fourWalkingBit` 翻转
        for (int position = start; position < end - 1; ++position) {
            flipbit(position * 8);
            flipbit((position + 1) * 8);  // 同时翻转相邻的两个比特
        }

        for (int position = start; position < end - 3; ++position) {
            flipbit(position * 8);
            flipbit((position + 1) * 8);
            flipbit((position + 2) * 8);
            flipbit((position + 3) * 8);  // 同时翻转相邻的四个位
        }

    } else {
        // 如果 isBitFlipFirst 为 false，执行强烈的 havoc 变异
        auto origin = curFuzzItem.data;
        bytes data = origin;
        int havocIterations = HAVOC_MIN;  // 使用一个较小的基准迭代次数

        // 变量移到 switch 语句外面
        u32 pos = 0;
        u32 useStacking = 1 << (1 + UR(HAVOC_STACK_POW2));
        for (int i = 0; i < havocIterations; i++) {
            for (u32 j = 0; j < useStacking; j++) {
                u32 mutationType = UR(11);  // 随机选择变异策略
                dataSize = data.size();
                byte* out_buf = data.data();

                switch (mutationType) {
                    case 0:  // 单个位翻转
                        pos = UR(dataSize << 3);
                        data[pos >> 3] ^= (128 >> (pos & 7));
                        break;

                    case 1:  // 将字节设置为感兴趣的值
                        data[UR(dataSize)] = INTERESTING_8[UR(sizeof(INTERESTING_8))];
                        break;

                    case 2:  // 将字设为感兴趣的值
                        if (dataSize < 2) break;
                        *(u16*)(out_buf + UR(dataSize - 1)) = INTERESTING_16[UR(sizeof(INTERESTING_16) / 2)];
                        break;

                    case 3:  // 将双字设为感兴趣的值
                        if (dataSize < 4) break;
                        *(u32*)(out_buf + UR(dataSize - 3)) = INTERESTING_32[UR(sizeof(INTERESTING_32) / 4)];
                        break;

                    case 4:  // 对字节随机加减
                        out_buf[UR(dataSize)] -= 1 + UR(ARITH_MAX);
                        break;

                    case 5:  // 对字节随机加法操作
                        out_buf[UR(dataSize)] += 1 + UR(ARITH_MAX);
                        break;

                    case 6:  // 对16位的值随机减法操作
                        if (dataSize < 2) break;
                        pos = UR(dataSize - 1);
                        *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
                        break;

                    case 7:  // 对16位的值随机加法操作
                        if (dataSize < 2) break;
                        pos = UR(dataSize - 1);
                        *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
                        break;

                    case 8:  // 对32位的值随机减法操作
                        if (dataSize < 4) break;
                        pos = UR(dataSize - 3);
                        *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
                        break;

                    case 9:  // 对32位的值随机加法操作
                        if (dataSize < 4) break;
                        pos = UR(dataSize - 3);
                        *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
                        break;

                    case 10:  // 随机修改一个字节
                        out_buf[UR(dataSize)] ^= 1 + UR(255);
                        break;

                    default:
                        out_buf[UR(dataSize)] ^= 1 + UR(255);
                        break;
                }
            }
        }
        curFuzzItem.data = data;
    }
}



void Mutation::mutate(OnMutateFunc cb,bool isfirstmutate) {
    stageName = "log-based mutation";
    stageMax = 1;
    bytes origin = curFuzzItem.data;
    
    //std::cout << "Old data: " << curFuzzItem.data << std::endl;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    double randomValue = dis(gen);

    // 20%的几率使用 _havoc 生成的数据
    if (randomValue < 0.2) {
        //std::cout << "Using _havoc data for mutation" << std::endl;
        curFuzzItem.data = _havoc();  // _havoc 是提供随机变异数据的函数     
    }else{
      // 遍历每个函数，检查其参数是否需要变异
      for (auto& fd : executive.ca.fds) {
          std::string funcName = fd.name;
  
          // 检查 mutateInfo 中是否包含此函数
          if (mutateInfo.find(funcName) != mutateInfo.end()) {
              auto& paramMap = mutateInfo[funcName];
  
              for (auto& td : fd.tds) {
                  std::string paramName = td.paraname;
  
                  // 检查参数是否需要变异
                  if (paramMap.find(paramName) != paramMap.end() && (paramMap[paramName] == "yes" || paramMap[paramName] == "Yes")) {
                      
                      // 利用 funcPositions 获取该参数的起始和结束位置
                      if (funcPositions.find(funcName) != funcPositions.end() && funcPositions[funcName].find(paramName) != funcPositions[funcName].end()) {
                          auto paramRange = funcPositions[funcName][paramName];
                          int start = paramRange.start;
                          int end = paramRange.end;
  
                          // 根据 start 和 end 对数据进行变异
                          mutateParamAtPosition(start, end,isfirstmutate);
                      }
                  }
              }
          }
      }
    }
    
    //std::cout << "New data: " << curFuzzItem.data << std::endl;

    // 调用回调函数处理新的测试用例
    cb(curFuzzItem.data);

    // 恢复原始数据，避免影响后续变异
    curFuzzItem.data = origin;
    stageCycles[STAGE_LOG] += stageMax;
}


bytes Mutation::_mutate(bool isfirstmutate) {
    stageName = "log-based mutation";
    stageMax = 1;
    bytes origin = curFuzzItem.data;
    
    //std::cout << "Old data: " << curFuzzItem.data << std::endl;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    double randomValue = dis(gen);

    // 20%的几率使用 _havoc 生成的数据
    if (randomValue < 0.2) {
        //std::cout << "Using _havoc data for mutation" << std::endl;
        curFuzzItem.data = _havoc();  // _havoc 是提供随机变异数据的函数     
    }else{
      // 遍历每个函数，检查其参数是否需要变异
      for (auto& fd : executive.ca.fds) {
          std::string funcName = fd.name;
  
          // 检查 mutateInfo 中是否包含此函数
          if (mutateInfo.find(funcName) != mutateInfo.end()) {
              auto& paramMap = mutateInfo[funcName];
  
              for (auto& td : fd.tds) {
                  std::string paramName = td.paraname;
  
                  // 检查参数是否需要变异
                  if (paramMap.find(paramName) != paramMap.end() && (paramMap[paramName] == "yes" || paramMap[paramName] == "Yes")) {
                      
                      // 利用 funcPositions 获取该参数的起始和结束位置
                      if (funcPositions.find(funcName) != funcPositions.end() && funcPositions[funcName].find(paramName) != funcPositions[funcName].end()) {
                          auto paramRange = funcPositions[funcName][paramName];
                          int start = paramRange.start;
                          int end = paramRange.end;
  
                          // 根据 start 和 end 对数据进行变异
                          mutateParamAtPosition(start, end,isfirstmutate);
                      }
                  }
              }
          }
      }
    }
    
    //std::cout << "New data: " << curFuzzItem.data << std::endl;
    return curFuzzItem.data;
}


void Mutation::flipbit(int pos) {
  curFuzzItem.data[pos >> 3] ^= (128 >> (pos & 7));
}

void Mutation::singleWalkingBit(OnMutateFunc cb) {
  stageName = "bitflip 1/1";
  stageMax = dataSize << 3;
  /* Start fuzzing */
  for (stageCur = 0; stageCur < stageMax ; stageCur += 1) {
    flipbit(stageCur);
    cb(curFuzzItem.data);
    flipbit(stageCur);
  }
  stageCycles[STAGE_FLIP1] += stageMax;
}

void Mutation::twoWalkingBit(OnMutateFunc cb) {
  stageName = "bitflip 2/1";
  stageMax = (dataSize << 3) - 1;
  /* Start fuzzing */
  for (stageCur = 0; stageCur < stageMax; stageCur += 1) {
    flipbit(stageCur);
    flipbit(stageCur + 1);
    cb(curFuzzItem.data);
    flipbit(stageCur);
    flipbit(stageCur + 1);
  }
  stageCycles[STAGE_FLIP2] += stageMax;
}

void Mutation::fourWalkingBit(OnMutateFunc cb) {
  stageName = "bitflip 4/1";
  stageMax = (dataSize << 3) - 3;
  /* Start fuzzing */
  for (stageCur = 0; stageCur < stageMax; stageCur += 1) {
    flipbit(stageCur);
    flipbit(stageCur + 1);
    flipbit(stageCur + 2);
    flipbit(stageCur + 3);
    cb(curFuzzItem.data);
    flipbit(stageCur);
    flipbit(stageCur + 1);
    flipbit(stageCur + 2);
    flipbit(stageCur + 3);
  }
  stageCycles[STAGE_FLIP4] += stageMax;
}

void Mutation::singleWalkingByte(OnMutateFunc cb) {
  stageName = "bitflip 8/8";
  stageMax = dataSize;
  /* Start fuzzing */
  for (stageCur = 0; stageCur < stageMax; stageCur += 1) {
    curFuzzItem.data[stageCur] ^= 0xFF;
    FuzzItem item = cb(curFuzzItem.data);
    /* We also use this stage to pull off a simple trick: we identify
     bytes that seem to have no effect on the current execution path
     even when fully flipped - and we skip them during more expensive
     deterministic stages, such as arithmetics or known ints. */
    if (!eff[effAPos(stageCur)]) {
      if (item.res.cksum != curFuzzItem.res.cksum) {
        eff[effAPos(stageCur)] = 1;
        effCount += 1;
      }
    }
    curFuzzItem.data[stageCur] ^= 0xFF;
  }
  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
   whole thing as worth fuzzing, since we wouldn't be saving much time
   anyway. */
  if (effCount != effALen(dataSize) && effCount * 100 / effALen(dataSize) > EFF_MAX_PERC) {
    eff = bytes(effALen(dataSize), 1);
  }
  stageCycles[STAGE_FLIP8] += stageMax;
}

void Mutation::twoWalkingByte(OnMutateFunc cb) {
  stageName = "bitflip 16/8";
  stageMax = dataSize - 1;
  stageCur = 0;
  /* Start fuzzing */
  u8 *buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 1; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      stageMax--;
      continue;
    }
    *(u16*)(buf + i) ^= 0xFFFF;
    cb(curFuzzItem.data);
    stageCur ++;
    *(u16*)(buf + i) ^= 0xFFFF;
  }
  stageCycles[STAGE_FLIP16] += stageMax;
}

void Mutation::fourWalkingByte(OnMutateFunc cb) {
  stageName = "bitflip 32/8";
  stageMax = dataSize - 3;
  stageCur = 0;
  /* Start fuzzing */
  u8 *buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 3; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] &&
        !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      stageMax --;
      continue;
    }
    *(u32*)(buf + i) ^= 0xFFFFFFFF;
    cb(curFuzzItem.data);
    stageCur ++;
    *(u32*)(buf + i) ^= 0xFFFFFFFF;
  }
  stageCycles[STAGE_FLIP32] += stageMax;
}

void Mutation::singleArith(OnMutateFunc cb) {
  stageName = "arith 8/8";
  stageMax = 2 * dataSize * ARITH_MAX;
  stageCur = 0;
  /* Start fuzzing */
  for (int i = 0; i < dataSize; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)]) {
      stageMax -= (2 * ARITH_MAX);
      continue;
    }
    byte orig = curFuzzItem.data[i];
    for (int j = 1; j <= ARITH_MAX; j += 1) {
      byte r = orig ^ (orig + j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig + j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      r = orig ^ (orig - j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig - j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      curFuzzItem.data[i] = orig;
    }
  }
  stageCycles[STAGE_ARITH8] += stageMax;
}

void Mutation::twoArith(OnMutateFunc cb) {
  stageName = "arith 16/8";
  stageMax = 4 * (dataSize - 1) * ARITH_MAX;
  stageCur = 0;
  /* Start fuzzing */
  byte *buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 1; i += 1) {
    u16 orig = *(u16*)(buf + i);
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      stageMax -= 4 * ARITH_MAX;
      continue;
    }
    for (int j = 1; j <= ARITH_MAX; j += 1) {
      u16 r1 = orig ^ (orig + j);
      u16 r2 = orig ^ (orig - j);
      u16 r3 = orig ^ swap16(swap16(orig) + j);
      u16 r4 = orig ^ swap16(swap16(orig) - j);
      if ((orig & 0xFF) + j > 0xFF && !couldBeBitflip(r1)) {
        *(u16*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((orig & 0xFF) < j && !couldBeBitflip(r2)) {
        *(u16*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((orig >> 8) + j > 0xFF && !couldBeBitflip(r3)) {
        *(u16*)(buf + i) = swap16(swap16(orig) + j);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((orig >> 8) < j && !couldBeBitflip(r4)) {
        *(u16*)(buf + i) = swap16(swap16(orig) - j);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      *(u16*)(buf + i) = orig;
    }
  }
  stageCycles[STAGE_ARITH16] += stageMax;
}

void Mutation::fourArith(OnMutateFunc cb) {
  stageName = "arith 32/8";
  stageMax = 4 * (dataSize - 3) * ARITH_MAX;
  stageCur = 0;
  /* Start fuzzing */
  byte *buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 3; i += 1) {
    u32 orig = *(u32*)(buf + i);
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] && !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      stageMax -= 4 * ARITH_MAX;
      continue;
    }
    for (int j = 1; j <= ARITH_MAX; j += 1) {
      u32 r1 = orig ^ (orig + j);
      u32 r2 = orig ^ (orig - j);
      u32 r3 = orig ^ swap32(swap32(orig) + j);
      u32 r4 = orig ^ swap32(swap32(orig) - j);
      if ((orig & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r1)) {
        *(u32*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((orig & 0xFFFF) < (u32)j && !couldBeBitflip(r2)) {
        *(u32*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((swap32(orig) & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r3)) {
        *(u32*)(buf + i) = swap32(swap32(orig) + j);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((swap32(orig) & 0xFFFF) < (u32) j && !couldBeBitflip(r4)) {
        *(u32*)(buf + i) = swap32(swap32(orig) - j);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      *(u32*)(buf + i) = orig;
    }
  }
  stageCycles[STAGE_ARITH32] += stageMax;
}

void Mutation::singleInterest(OnMutateFunc cb) {
  stageName = "interest 8/8";
  stageMax = dataSize * sizeof(INTERESTING_8);
  stageCur = 0;
  /* Start fuzzing */
  for (int i = 0; i < dataSize; i += 1) {
    u8 orig = curFuzzItem.data[i];
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)]) {
      stageMax -= sizeof(INTERESTING_8);
      continue;
    }
    for (int j = 0; j < (int) sizeof(INTERESTING_8); j += 1) {
      if (couldBeBitflip(orig ^ (u8)INTERESTING_8[j]) || couldBeArith(orig, (u8)INTERESTING_8[j], 1)) {
        stageMax --;
        continue;
      }
      curFuzzItem.data[i] = INTERESTING_8[j];
      cb(curFuzzItem.data);
      stageCur ++;
      curFuzzItem.data[i] = orig;
    }
  }
  stageCycles[STAGE_INTEREST8] += stageMax;
}

void Mutation::twoInterest(OnMutateFunc cb) {
  stageName = "interest 16/8";
  stageMax = 2 * (dataSize - 1) * (sizeof(INTERESTING_16) >> 1);
  stageCur = 0;
  /* Start fuzzing */
  byte *out_buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 1; i += 1) {
    u16 orig = *(u16*)(out_buf + i);
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      stageMax -= sizeof(INTERESTING_16);
      continue;
    }
    for (int j = 0; j < (int) sizeof(INTERESTING_16) / 2; j += 1) {
      if (!couldBeBitflip(orig ^ (u16)INTERESTING_16[j]) &&
          !couldBeArith(orig, (u16)INTERESTING_16[j], 2) &&
          !couldBeInterest(orig, (u16)INTERESTING_16[j], 2, 0)) {
        *(u16*)(out_buf + i) = INTERESTING_16[j];
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;

      if ((u16)INTERESTING_16[j] != swap16(INTERESTING_16[j]) &&
          !couldBeBitflip(orig ^ swap16(INTERESTING_16[j])) &&
          !couldBeArith(orig, swap16(INTERESTING_16[j]), 2) &&
          !couldBeInterest(orig, swap16(INTERESTING_16[j]), 2, 1)) {
        *(u16*)(out_buf + i) = swap16(INTERESTING_16[j]);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
    }
    *(u16*)(out_buf + i) = orig;
  }
  stageCycles[STAGE_INTEREST16] += stageMax;
}

void Mutation::fourInterest(OnMutateFunc cb) {
  stageName = "interest 32/8";
  stageMax = 2 * (dataSize - 3) * (sizeof(INTERESTING_32) >> 2);
  stageCur = 0;
  /* Start fuzzing */
  byte *out_buf = curFuzzItem.data.data();
  for (int i = 0; i < dataSize - 3; i++) {
    u32 orig = *(u32*)(out_buf + i);
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] &&
        !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      stageMax -= sizeof(INTERESTING_32) >> 1;
      continue;
    }
    for (int j = 0; j < (int) sizeof(INTERESTING_32) / 4; j++) {
      /* Skip if this could be a product of a bitflip, arithmetics,
       or word interesting value insertion. */
      if (!couldBeBitflip(orig ^ (u32)INTERESTING_32[j]) &&
          !couldBeArith(orig, INTERESTING_32[j], 4) &&
          !couldBeInterest(orig, INTERESTING_32[j], 4, 0)) {
        *(u32*)(out_buf + i) = INTERESTING_32[j];
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
      if ((u32)INTERESTING_32[j] != swap32(INTERESTING_32[j]) &&
          !couldBeBitflip(orig ^ swap32(INTERESTING_32[j])) &&
          !couldBeArith(orig, swap32(INTERESTING_32[j]), 4) &&
          !couldBeInterest(orig, swap32(INTERESTING_32[j]), 4, 1)) {
        *(u32*)(out_buf + i) = swap32(INTERESTING_32[j]);
        cb(curFuzzItem.data);
        stageCur ++;
      } else stageMax --;
    }
    *(u32*)(out_buf + i) = orig;
  }
  stageCycles[STAGE_INTEREST32] += stageMax;
}

void Mutation::overwriteWithDictionary(OnMutateFunc cb) {
  stageName = "dict (over)";
  auto dict = get<0>(dicts);
  stageMax = dataSize * dict.extras.size();
  stageCur = 0;
  /* Start fuzzing */
  byte *outBuf = curFuzzItem.data.data();
  byte inBuf[curFuzzItem.data.size()];
  memcpy(inBuf, outBuf, curFuzzItem.data.size());
  u32 extrasCount = dict.extras.size();
  /*
   * In solidity - data block is 32 bytes then change to step = 32, not 1
   * Size of extras is alway 32
   */
  for (u32 i = 0; i < (u32)dataSize; i += 1) {
    u32 lastLen = 0;
    for (u32 j = 0; j < extrasCount; j += 1) {
      byte *extrasBuf = dict.extras[j].data.data();
      byte *effBuf = eff.data();
      u32 extrasLen = dict.extras[j].data.size();
      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
       skip them if there's no room to insert the payload, if the token
       is redundant, or if its entire span has no bytes set in the effector
       map. */
      if ((extrasCount > MAX_DET_EXTRAS
          && UR(extrasCount) > MAX_DET_EXTRAS)
          || extrasLen > (dataSize - i)
          || !memcmp(extrasBuf, outBuf + i, extrasLen)
          || !memchr(effBuf + effAPos(i), 1, effSpanALen(i, extrasLen))
          ) {
        stageMax --;
        continue;
      }
      lastLen = extrasLen;
      memcpy(outBuf + i, extrasBuf, lastLen);
      cb(curFuzzItem.data);
      stageCur ++;
    }
    /* Restore all the clobbered memory. */
    memcpy(outBuf + i, inBuf + i, lastLen);
  }
  stageCycles[STAGE_EXTRAS_UO] += stageMax;
}

void Mutation::overwriteWithAddressDictionary(OnMutateFunc cb) {
  stageName = "address (over)";
  auto dict = get<1>(dicts);

  stageMax = (dataSize / 32) * dict.extras.size();
  stageCur = 0;
  /* Start fuzzing */
  byte *outBuf = curFuzzItem.data.data();
  byte inBuf[curFuzzItem.data.size()];
  memcpy(inBuf, outBuf, curFuzzItem.data.size());
  u32 extrasCount = dict.extras.size();
  u32 extrasLen = 20;
  for (u32 i = 0; i < (u32)dataSize; i += 32) {
    for (u32 j = 0; j < extrasCount; j += 1) {
      byte *extrasBuf = dict.extras[j].data.data();
      if (!memcmp(extrasBuf, outBuf + i + 12, extrasLen)) {
        stageMax --;
        continue;
      }
      memcpy(outBuf + i + 12, extrasBuf, extrasLen);
      cb(curFuzzItem.data);
      stageCur ++;
    }
    /* Restore all the clobbered memory. */
    memcpy(outBuf + i, inBuf + i, 32);
  }
  stageCycles[STAGE_EXTRAS_AO] += stageMax;
}

/*
 * TODO: If found more, do more havoc
 */
void Mutation::havoc(OnMutateFunc cb) {
  stageName = "havoc";
  stageMax = HAVOC_MIN;
  stageCur = 0;

  auto dict = get<0>(dicts);
  auto origin = curFuzzItem.data;
  bytes data = origin;
  for (int i = 0; i < HAVOC_MIN; i += 1) {
    u32 useStacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    for (u32 j = 0; j < useStacking; j += 1) {
      u32 val = UR(11 + ((dict.extras.size() + 0) ? 2 : 0));
      dataSize = data.size();
      byte *out_buf = data.data();
      switch (val) {
        case 0: {
          /* Flip a single bit somewhere. Spooky! */
          u32 pos = UR(dataSize << 3);
          data[pos >> 3] ^= (128 >> (pos & 7));
          break;
        }
        case 1: {
          /* Set byte to interesting value. */
          data[UR(dataSize)] = INTERESTING_8[UR(sizeof(INTERESTING_8))];
          break;
        }
        case 2: {
          /* Set word to interesting value, randomly choosing endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            *(u16*)(out_buf + UR(dataSize - 1)) = INTERESTING_16[UR(sizeof(INTERESTING_16) >> 1)];
          } else {
            *(u16*)(out_buf + UR(dataSize - 1)) = swap16(INTERESTING_16[UR(sizeof(INTERESTING_16) >> 1)]);
          }
          break;
        }
        case 3: {
          /* Set dword to interesting value, randomly choosing endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            *(u32*)(out_buf + UR(dataSize - 3)) = INTERESTING_32[UR(sizeof(INTERESTING_32) >> 2)];
          } else {
            *(u32*)(out_buf + UR(dataSize - 3)) = swap32(INTERESTING_32[UR(sizeof(INTERESTING_32) >> 2)]);
          }
          break;
        }
        case 4: {
          /* Randomly subtract from byte. */
          out_buf[UR(dataSize)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 5: {
          /* Randomly add to byte. */
          out_buf[UR(dataSize)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 6: {
          /* Randomly subtract from word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) - num);
          }
          break;
        }
        case 7: {
          /* Randomly add to word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) + num);
          }
          break;
        }
        case 8: {
          /* Randomly subtract from dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) - num);
          }
          break;
        }
        case 9: {
          /* Randomly add to dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) + num);
          }
          break;
        }
        case 10: {
          /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */
          out_buf[UR(dataSize)] ^= 1 + UR(255);
          break;
        }
        case 11: {
          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
           bytes (25%). */
          u32 copyFrom, copyTo, copyLen;
          if (dataSize < 2) break;
          copyLen = chooseBlockLen(dataSize - 1);
          copyFrom = UR(dataSize - copyLen + 1);
          copyTo = UR(dataSize - copyLen + 1);
          if (UR(4)) {
            if (copyFrom != copyTo)
              memmove(out_buf + copyTo, out_buf + copyFrom, copyLen);
          } else {
            memset(out_buf + copyTo, UR(2) ? UR(256) : out_buf[UR(dataSize)], copyLen);
          }
          break;
        }
        case 12: {
          /* No auto extras or odds in our favor. Use the dictionary. */
          u32 useExtra = UR(dict.extras.size());
          u32 extraLen = dict.extras[useExtra].data.size();
          byte *extraBuf = dict.extras[useExtra].data.data();
          u32 insertAt;
          if (extraLen > (u32)dataSize) break;
          insertAt = UR(dataSize - extraLen + 1);
          memcpy(out_buf + insertAt, extraBuf, extraLen);
          break;
        }
      }
    }
    cb(data);
    stageCur ++;
    /* Restore to original state */
    data = origin;
  }
  stageCycles[STAGE_HAVOC] += stageMax;
}

bytes Mutation::test() {
  auto origin = curFuzzItem.data;
  return origin;
}

bytes Mutation::_havoc() {
  stageName = "havoc";
  stageMax = HAVOC_MIN;
  stageCur = 0;
  

  auto dict = get<0>(dicts);
  auto origin = curFuzzItem.data;
  bytes data = origin;
  for (int i = 0; i < HAVOC_MIN; i += 1) {
    u32 useStacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    for (u32 j = 0; j < useStacking; j += 1) {
      u32 val = UR(11 + ((dict.extras.size() + 0) ? 2 : 0));
      dataSize = data.size();
      byte *out_buf = data.data();
      switch (val) {
        case 0: {
          /* Flip a single bit somewhere. Spooky! */
          u32 pos = UR(dataSize << 3);
          data[pos >> 3] ^= (128 >> (pos & 7));
          break;
        }
        case 1: {
          /* Set byte to interesting value. */
          data[UR(dataSize)] = INTERESTING_8[UR(sizeof(INTERESTING_8))];
          break;
        }
        case 2: {
          /* Set word to interesting value, randomly choosing endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            *(u16*)(out_buf + UR(dataSize - 1)) = INTERESTING_16[UR(sizeof(INTERESTING_16) >> 1)];
          } else {
            *(u16*)(out_buf + UR(dataSize - 1)) = swap16(INTERESTING_16[UR(sizeof(INTERESTING_16) >> 1)]);
          }
          break;
        }
        case 3: {
          /* Set dword to interesting value, randomly choosing endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            *(u32*)(out_buf + UR(dataSize - 3)) = INTERESTING_32[UR(sizeof(INTERESTING_32) >> 2)];
          } else {
            *(u32*)(out_buf + UR(dataSize - 3)) = swap32(INTERESTING_32[UR(sizeof(INTERESTING_32) >> 2)]);
          }
          break;
        }
        case 4: {
          /* Randomly subtract from byte. */
          out_buf[UR(dataSize)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 5: {
          /* Randomly add to byte. */
          out_buf[UR(dataSize)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 6: {
          /* Randomly subtract from word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) - num);
          }
          break;
        }
        case 7: {
          /* Randomly add to word, random endian. */
          if (dataSize < 2) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 1);
            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(out_buf + pos) = swap16(swap16(*(u16*)(out_buf + pos)) + num);
          }
          break;
        }
        case 8: {
          /* Randomly subtract from dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) - num);
          }
          break;
        }
        case 9: {
          /* Randomly add to dword, random endian. */
          if (dataSize < 4) break;
          if (UR(2)) {
            u32 pos = UR(dataSize - 3);
            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(dataSize - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(out_buf + pos) = swap32(swap32(*(u32*)(out_buf + pos)) + num);
          }
          break;
        }
        case 10: {
          /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */
          out_buf[UR(dataSize)] ^= 1 + UR(255);
          break;
        }
        case 11: {
          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
           bytes (25%). */
          u32 copyFrom, copyTo, copyLen;
          if (dataSize < 2) break;
          copyLen = chooseBlockLen(dataSize - 1);
          copyFrom = UR(dataSize - copyLen + 1);
          copyTo = UR(dataSize - copyLen + 1);
          if (UR(4)) {
            if (copyFrom != copyTo)
              memmove(out_buf + copyTo, out_buf + copyFrom, copyLen);
          } else {
            memset(out_buf + copyTo, UR(2) ? UR(256) : out_buf[UR(dataSize)], copyLen);
          }
          break;
        }
        case 12: {
          /* No auto extras or odds in our favor. Use the dictionary. */
          u32 useExtra = UR(dict.extras.size());
          u32 extraLen = dict.extras[useExtra].data.size();
          byte *extraBuf = dict.extras[useExtra].data.data();
          u32 insertAt;
          if (extraLen > (u32)dataSize) break;
          insertAt = UR(dataSize - extraLen + 1);
          memcpy(out_buf + insertAt, extraBuf, extraLen);
          break;
        }
      }
    }   
    return data;
    stageCur ++;
    /* Restore to original state */
    data = origin;
  }
}








