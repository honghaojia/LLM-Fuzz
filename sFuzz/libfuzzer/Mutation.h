#pragma once
#include <vector>
#include "Common.h"
#include "TargetContainer.h"
#include "Dictionary.h"
#include "FuzzItem.h"
#include "LLMhelper.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  using Dicts = tuple<Dictionary/* code */, Dictionary/* address */>;
  class Mutation {
    Dicts dicts;
    TargetExecutive executive;
    std::string contractName;
    uint64_t effCount = 0;
    bytes eff;
    void flipbit(int pos);
    struct ParamPosition {
      size_t start;
      size_t end;
    };
    
    
    
    
    public:
      FuzzItem curFuzzItem;
      
      // 记录函数的每个参数的位置信息
      std::unordered_map<std::string, std::unordered_map<std::string, ParamPosition>> funcPositions;
  
      // 填充函数参数位置
      void populateParamPositions();
  
      // 根据函数名获取变异的部分
      std::vector<std::pair<size_t, size_t>> getMutateSections(const std::string& functionName);
      
      std::unordered_map<std::string, std::unordered_map<std::string, std::string>> mutateInfo;
      Mutation(FuzzItem item, Dicts dicts,TargetExecutive& executive,std::string contractName);
      void initMutateInfo();
      void updateMutationStrategy(std::string& file_path);
      std::unordered_map<std::string, std::unordered_map<std::string, std::string>> parseModelFeedback(const std::string& feedback);
      void mutateParamAtPosition(int start, int end,bool isfirstmutate);
      int findParamPositionInData(FuncDef& fd,const std::string& paramName);
      void mutate(OnMutateFunc cb,bool isfirstmutate);
      bytes _mutate(bool isfirstmutate);
      
      uint64_t dataSize = 0;
      uint64_t stageMax = 0;
      uint64_t stageCur = 0;
      string stageName = "";
      static uint64_t stageCycles[32];
      void singleWalkingBit(OnMutateFunc cb);
      void twoWalkingBit(OnMutateFunc cb);
      void fourWalkingBit(OnMutateFunc cb);
      void singleWalkingByte(OnMutateFunc cb);
      void twoWalkingByte(OnMutateFunc cb);
      void fourWalkingByte(OnMutateFunc cb);
      void singleArith(OnMutateFunc cb);
      void twoArith(OnMutateFunc cb);
      void fourArith(OnMutateFunc cb);
      void singleInterest(OnMutateFunc cb);
      void twoInterest(OnMutateFunc cb);
      void fourInterest(OnMutateFunc cb);
      void overwriteWithAddressDictionary(OnMutateFunc cb);
      void overwriteWithDictionary(OnMutateFunc cb);
      void random(OnMutateFunc cb,std::string& file_path,std::string execution_order);
      void havoc(OnMutateFunc cb);
      bool splice(vector<FuzzItem> items);
      bytes _havoc();
      bytes test();
      
      
      
      
      
  };
}
