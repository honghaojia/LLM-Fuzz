#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "LLMhelper.h"
#include <unordered_map> // 新增
#include <map>           // 新增

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { AFL };
  enum Reporter { TERMINAL, JSON, BOTH };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    vector<string> constantFunctionSrcmap;
    bool isMain;
  };
  struct FuzzParam {
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int analyzingInterval;
    string attackerName;
    string filepath;
    string contractName;
    string folderName;
  };
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
    int lastVulnerabilities = 0;
    double lastCoverage = 0.0;
    std::vector<std::string> currentOrder;
  };
  struct Leader {
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue): item(_item) {
      comparisonValue = _comparisionValue;
    }
  };
  class Fuzzer {
    double smallTestTime = 5.0;
    double evaluateTime = 20.0;
    double showStatTime = 20.0;
    double maxCoverageIncrement = 0.15;
    int writeStatCounts = 1;
    bool randomOrder = false;
    int stateFdsSize = 0;
    double totalTestTime;
    bool isfirstTime = true;
    bool newBranchCoverd = false;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> mutateInfo;
    std::map<std::vector<std::string>, int> selectionCounts;
    std::vector<std::pair<std::vector<std::string>, double>> executionOrdersWithScores;
    double averageScore = 0.0;
    vector<bool> vulnerabilities;
    vector<string> queues;
    unordered_set<string> tracebits;
    unordered_set<string> predicates;
    unordered_map<string, Leader> leaders;
    unordered_map<uint64_t, string> snippets;
    unordered_set<string> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(const Mutation &mutation,const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
    int calculateOrdersToGenerate(int numFunctions);
    double runPreliminaryTests(TargetExecutive& executive, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,TargetContainer& container,Dictionary codeDict, Dictionary addressDict);
    void insertExecutionOrder(const std::vector<std::string>& functionOrder, double score);
    void sortExecutionOrders();
    const std::vector<pair<std::vector<std::string>, double>>& getExecutionOrdersWithScores() const;
    double calculateAverageScore() const;
    std::vector<std::string> findHighestScoreOrder() const;
    void updateCurrentExecutionOrderScore(double increment);
    void removeLowestScoreOrders();
    void evaluateAndSelectOptimalOrder(TargetExecutive& executive,TargetContainer& container,const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis);
    FuzzItem saveIfInterest1(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis);
    void writeCoverageInfo(const std::string& contractName, const std::unordered_set<std::string>& tracebits, const std::vector<bool>& vulnerabilities, uint64_t totalPaths);
    
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void updateTracebits(unordered_set<string> tracebits);
      void updatePredicates(unordered_map<string, u256> predicates);
      void updateExceptions(unordered_set<string> uniqExceptions);
      void generateExecutionOrders(std::string filepath,const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,Dictionary codeDict, Dictionary addressDict,TargetExecutive& executive,TargetContainer& container);
      
      void start();
      void stop();
  };
}
