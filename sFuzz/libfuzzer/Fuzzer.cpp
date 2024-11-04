#include <fstream>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"
#include "BytecodeBranch.h"
#include <sstream>
#include <algorithm> // for std::random_shuffle
#include <random>    // for std::random_device and std::mt19937
#include <chrono>    // for std::chrono

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
namespace pt = boost::property_tree;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam): fuzzParam(fuzzParam){
  fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
void Fuzzer::updateExceptions(unordered_set<string> exps) {
  for (auto it: exps) uniqExceptions.insert(it);
}

/* Detect new bits by comparing tracebits to virginbits */
void Fuzzer::updateTracebits(unordered_set<string> _tracebits) {
  for (auto it: _tracebits) tracebits.insert(it);
}

void Fuzzer::updatePredicates(unordered_map<string, u256> _pred) {
  for (auto it : _pred) {
    predicates.insert(it.first);
  };
  // Remove covered predicates
  for(auto it = predicates.begin(); it != predicates.end(); ) {
    if (tracebits.count(*it)) {
      it = predicates.erase(it);
    } else {
      ++it;
    }
  }
}

// 动态计算要生成的执行顺序数量
int Fuzzer::calculateOrdersToGenerate(int numFunctions) {
    if (numFunctions <= 4) {
        // 小于等于4个函数时，生成所有可能的执行顺序（全排列）
        return std::tgamma(numFunctions + 1);  // 阶乘 n!
    } else {
        // 大于4个函数时，生成函数数量的一半的顺序
        return numFunctions / 2;
    }
}


// 插入新的函数执行顺序和得分
void Fuzzer::insertExecutionOrder(const std::vector<std::string>& functionOrder, double score) {
    executionOrdersWithScores.push_back({functionOrder, score});
}

// 对执行顺序进行排序，按得分降序排列
void Fuzzer::sortExecutionOrders() {
    std::sort(executionOrdersWithScores.begin(), executionOrdersWithScores.end(),
        [](const pair<std::vector<std::string>, double>& a, const pair<std::vector<std::string>, double>& b) {
            return a.second > b.second; // 按得分降序排列
        });
}

// 删除得分最低的交易序列，保留前 10 个
void Fuzzer::removeLowestScoreOrders() {
    // 首先对交易序列按得分降序进行排序
    sortExecutionOrders();

    // 确保有足够的交易序列
    if (executionOrdersWithScores.size() > 10) {
        // 删除最后 5 个交易序列
        executionOrdersWithScores.erase(executionOrdersWithScores.begin() + 10, executionOrdersWithScores.end());
        std::cout << "Deleted the 5 lowest scoring execution orders, kept the top 10." << std::endl;
    } else {
        std::cout << "Not enough execution orders to delete, kept all current orders." << std::endl;
    }
}

// 获取所有记录的执行顺序和得分
const std::vector<pair<std::vector<std::string>, double>>& Fuzzer::getExecutionOrdersWithScores() const {
    return executionOrdersWithScores;
}

// 计算所有执行顺序的平均得分
double Fuzzer::calculateAverageScore() const {
    if (executionOrdersWithScores.empty()) {
        return 0.0; // 如果列表为空，返回 0
    }

    double totalScore = 0.0;
    for (const auto& entry : executionOrdersWithScores) {
        totalScore += entry.second; // 累加每个执行顺序的得分
    }

    // 计算平均得分
    double averageScore = totalScore / executionOrdersWithScores.size();
    return averageScore;
}

// 更新当前执行顺序的得分
void Fuzzer::updateCurrentExecutionOrderScore(double increment) {
    auto& currentOrder = fuzzStat.currentOrder; // 获取当前函数执行顺序

    // 更新选择次数
    selectionCounts[currentOrder]++;

    // 获取选择次数
    int count = selectionCounts[currentOrder];

    // 定义基础衰减系数
    double baseDecayFactor = 0.95;

    // 计算衰减系数，指数级下降
    double decayFactor = std::pow(baseDecayFactor, count);

    // 在 executionOrdersWithScores 中找到对应的条目并更新得分
    for (auto& entry : executionOrdersWithScores) {
        if (entry.first == currentOrder) { // 比较函数执行顺序
            // 应用衰减系数并更新得分
            entry.second = entry.second * decayFactor + increment;
            // 设置得分的最小值，防止过低
            double minScore = 0.1;
            entry.second = std::max(entry.second, minScore);
            break; // 找到并更新后退出循环
        }
    }

    // 对执行顺序列表进行排序
    sortExecutionOrders();
}

//从所有函数执行顺序中找到最好的那个
std::vector<std::string> Fuzzer::findHighestScoreOrder() const {
    // 定义随机选择的概率（20% 随机选择，80% 选择最高得分）
    double randomSelectionProbability = 0.2;

    // 生成一个0到1之间的随机数
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    double randomValue = dis(gen);

    // 判断是否进行随机选择
    if (randomValue < randomSelectionProbability) {
        // 随机选择一个执行顺序
        std::uniform_int_distribution<> indexDist(0, executionOrdersWithScores.size() - 1);
        int randomIndex = indexDist(gen);
        return executionOrdersWithScores[randomIndex].first; // 返回随机选择的执行顺序
    } else {
        // 找到最高得分的执行顺序
        auto bestOrder = *std::max_element(executionOrdersWithScores.begin(), executionOrdersWithScores.end(),
            [](const std::pair<std::vector<std::string>, double>& a, const std::pair<std::vector<std::string>, double>& b) {
                return a.second < b.second; // 找到得分最高的元素
            });
        return bestOrder.first; // 返回得分最高的执行顺序
    }
}


// 进行小范围测试，每个执行顺序测试10秒
double Fuzzer::runPreliminaryTests(TargetExecutive& executive, 
                                   const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,TargetContainer& container,Dictionary codeDict, Dictionary addressDict) {
    auto startTime = timer.elapsed();
    auto elapsedTime = 0;
    int originHitCount = leaders.size();
    int numVulnerabilities = 0;
    
    // 每次测试时创建一个当前测试用例的变异器
    bytes data = executive.ca.randomTestcase(fuzzParam.filepath);
    
    FuzzItem curItem(data);
    Mutation mutation(curItem, make_tuple(codeDict, addressDict),executive,fuzzParam.contractName);
    bool isfirstmutate = true;

    // 进行小范围的模糊测试
    while (elapsedTime < smallTestTime) {
        data = mutation._mutate(isfirstmutate);
        if (isfirstmutate == true){
          isfirstmutate=false;
        }
        mutation.curFuzzItem.data = data;
        // 对生成的测试用例进行变异，使用与正式模糊测试相同的变异方式
        saveIfInterest(executive, data, 0, validJumpis);
        
        // 计算已用时间
        auto now = timer.elapsed();
        elapsedTime = now-startTime;
    }
    
    // 分析检测到的漏洞
    vulnerabilities = container.analyze();
    
    // 定义漏洞类型名称
    std::vector<std::string> vulnerabilityNames = {
        "Gasless Send", 
        "Exception Disorder", 
        "Time Dependency", 
        "Block Number Dependency", 
        "Delegate Call", 
        "Reentrancy", 
        "Freezing", 
        "Underflow", 
        "Overflow",
        "Unchecked Call",
        "Suicidal"
    };
    
    // 打印检测到的漏洞类型
    std::cout << "Detected Vulnerabilities: " << std::endl;
    for (size_t i = 0; i < vulnerabilities.size(); ++i) {
        if (vulnerabilities[i]) {
            std::cout << "- " << vulnerabilityNames[i] << std::endl;
            numVulnerabilities++;
        }
    }

    std::cout << "small test spent " << elapsedTime << " seconds" << std::endl;

    // 计算总分支数量
    auto totalBranches = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;
    if (totalBranches == 0) totalBranches = 1; // 防止除0错误

    // 根据公式计算代码覆盖率
    auto coverage = (uint64_t)((float) tracebits.size() / (float) totalBranches * 100);

    std::cout << "Coverage: " << coverage << "%, Vulnerabilities: " << numVulnerabilities << std::endl;

    // 根据代码覆盖率和漏洞发现数量计算得分
    double score = coverage*0.0089 + numVulnerabilities * 0.01;  // 发现一个漏洞加10分，覆盖1%加1分
    
    tracebits.clear();
    leaders.clear();
    queues.clear();
    std::vector<bool> vulnerabilities(9, false); // 9个漏洞类型的数组，初始值为0
    container.oracleFactory->vulnerabilities = vulnerabilities;

    return score;
}


// 更新generateExecutionOrders，添加小范围模糊测试的打分逻辑
void Fuzzer::generateExecutionOrders(std::string filepath,const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,Dictionary codeDict, Dictionary addressDict,TargetExecutive& executive,TargetContainer& container) {

    std::string functionAPIs = executive.ca.generateFunctionAPIs(fuzzParam.contractName);

    std::vector<std::string> existingOrders;
    std::vector<std::string> order;
    int numFunctions = executive.ca.originalFds.size();
    int numOrders = 15;
    //int numOrders = 1;
    
    // 获取原始函数名列表
    std::vector<std::string> functionList;
    for (int i = 1; i <= numFunctions; ++i) {
        functionList.push_back(std::to_string(i)); // 函数的名称为 '1', '2', '3', ... 等
    }

    // 使用随机生成器
    std::random_device rd;
    std::mt19937 g(rd());
    
    
    auto start = timer.elapsed();
    // 根据传入的 numOrders 生成执行顺序
    for (int i = 0; i < numOrders; ++i) {
        if(randomOrder){
          order = functionList;  // 复制原始函数列表
          std::shuffle(order.begin(), order.end(), g);    // 随机打乱顺序
        }else{
          // 调用 generateExecutionOrder 生成新的执行顺序
          order = generateExecutionOrder(filepath, functionAPIs, existingOrders);
        }
        auto result = executive.ca.isValidOrder(order);
        bool isValid = result.first;
        if (isValid){
          order = result.second;
        }else{
           i--;
           continue;
        }
        
        // 将顺序组合成字符串
        std::string orderStr;
        for (const auto& func : order) {
            orderStr += func + "->";
        }
        if (!orderStr.empty()) {
            orderStr.pop_back();
            orderStr.pop_back();
        }
    

        // 检查与之前顺序的编辑距离
        bool isUnique = true;
        for (const auto& existingOrder : existingOrders) {
            if (calculateEditDistance(orderStr, existingOrder) < 2) {
                isUnique = false;
                break;
            }
        }
        if (!isUnique) {
            i--;
            continue;
        }
        
        std::cout << "Generated Execution Order " << i + 1 << ": " << orderStr << std::endl;
        executive.ca.setExecutionOrder(order);

        // 创建执行环境并进行小范围测试
        auto bin = fromHex(mainContract().bin);
        double score = runPreliminaryTests(executive, validJumpis,container,codeDict,addressDict);
        std::cout << "test score is : " << score <<std::endl;
        
        //double score = 0;

        // 存储执行顺序和得分
        insertExecutionOrder(order, score);

        // 将新生成的顺序添加到 existingOrders 中，避免重复
        existingOrders.push_back(orderStr);
    }
    
    // 根据得分排序执行顺序
    sortExecutionOrders();
    //removeLowestScoreOrders();
}

//评估每次函数执行顺序
void Fuzzer::evaluateAndSelectOptimalOrder(TargetExecutive& executive,TargetContainer& container,const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
    // 1. 分析检测到的漏洞
    int numVulnerabilities = 0;
    vulnerabilities = container.analyze();

    for (size_t i = 0; i < vulnerabilities.size(); ++i) {
        if (vulnerabilities[i]) {
            numVulnerabilities++;
        }
    }

    // 2. 计算当前覆盖率
    auto totalBranches = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;
    if (totalBranches == 0) totalBranches = 1; // 防止除0错误

    double currentCoverage = ((double) tracebits.size() / (double) totalBranches) * 100.0;

    // 5. 计算覆盖率增量和漏洞发现增量
    double coverageIncrement = currentCoverage - fuzzStat.lastCoverage;
    int vulnerabilityIncrement = numVulnerabilities - fuzzStat.lastVulnerabilities;


    // 更新 lastCoverage 和 lastVulnerabilities
    fuzzStat.lastCoverage = currentCoverage;
    fuzzStat.lastVulnerabilities = numVulnerabilities;

    // 6. 归一化处理
    double normalizedCoverageIncrement = coverageIncrement *0.0089;
    double normalizedVulnerabilityIncrement = (double)vulnerabilityIncrement *0.01;

    // 7. 计算正向得分
    double positiveScore = normalizedCoverageIncrement+normalizedVulnerabilityIncrement;
    
    double maxCoverageIncrement = 0.15; // 最大覆盖率增量，例如 5%
    positiveScore = std::min(positiveScore, maxCoverageIncrement);

    if(!isfirstTime){ 
      updateCurrentExecutionOrderScore(positiveScore);
  
      // 10. 选择得分最高的执行顺序
      std::vector<std::string> optimalOrder = findHighestScoreOrder();
      executive.ca.setExecutionOrder(optimalOrder);
      fuzzStat.currentOrder = optimalOrder;
        
      std::string currentOrder = executive.ca.getCurrentExecutionOrder();
      std::cout <<"current execution order is:" << currentOrder <<std::endl;
  
      // 输出当前所有执行顺序的得分，便于调试
      std::cout << "Current execution orders and scores:" << std::endl;
      for (const auto& entry : executionOrdersWithScores) {
          std::cout << "Order: ";
          for (const auto& func : entry.first) {
              std::cout << func << " ";
          }
          std::cout << ", Score: " << entry.second << std::endl;
      }
    }else{
      isfirstTime = false;
    }
    
}




ContractInfo Fuzzer::mainContract() {
  auto contractInfo = fuzzParam.contractInfo;
  auto first = contractInfo.begin();
  auto last = contractInfo.end();
  auto predicate = [](const ContractInfo& c) { return c.isMain; };
  auto it = find_if(first, last, predicate);
  return *it;
}

void Fuzzer::showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis) {
  /*
  int numLines = 26, i = 0;
  if (!fuzzStat.clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    fuzzStat.clearScreen = true;
  }
  */
  
  cout << "----------------------------------------" << endl;
  
  double duration = timer.elapsed()-totalTestTime;
  double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
  //for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 20);
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = mutation.stageMax == 0 ? to_string(100) : to_string((uint64_t)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
  auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
  auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);
  auto cyclePercentage = (uint64_t)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
  auto cycleProgress = padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
  auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
  auto totalBranches = (get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
  auto numBranches = padStr(to_string(totalBranches), 15);
  auto coverage = padStr(to_string((uint64_t)((float) tracebits.size() / (float) totalBranches * 100)) + "%", 15);
  auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP1]);
  auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP2]);
  auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP4]);
  auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
  auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP8]);
  auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP16]);
  auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP32]);
  auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
  auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH8]);
  auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH16]);
  auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH32]);
  auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
  auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST8]);
  auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST16]);
  auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST32]);
  auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
  auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
  auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
  auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
  auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" + to_string(mutation.stageCycles[STAGE_HAVOC]);
  auto havoc = padStr(hav1, 30);
  auto mutebylog1 = to_string(fuzzStat.stageFinds[STAGE_LOG]) + "/" + to_string(mutation.stageCycles[STAGE_LOG]);
  auto mutebylog = padStr(mutebylog1, 30);
  auto random1 = to_string(fuzzStat.stageFinds[STAGE_RANDOM]) + "/" + to_string(mutation.stageCycles[STAGE_RANDOM]);
  auto random = padStr(random1, 30);
  auto pending = padStr(to_string(leaders.size() - fuzzStat.idx), 5);
  auto fav = count_if(leaders.begin(), leaders.end(), [](const pair<string, Leader> &p) {
    return !p.second.item.fuzzedCount;
  });
  auto pendingFav = padStr(to_string(fav), 5);
  auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
  auto exceptionCount = padStr(to_string(uniqExceptions.size()), 5);
  auto predicateSize = padStr(to_string(predicates.size()), 5);
  auto contract = mainContract();
  auto toResult = [](bool val) { return val ? "found" : "none "; };
  printf(cGRN Bold "%sAFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(), fuzzParam.contractName.substr(0, 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
  printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(), numBranches.c_str());
  printf(bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(), coverage.c_str());
  printf(bH "  exec speed : %s" bH "               %s" bH "\n", execSpeed.c_str(), padStr("", 15).c_str());
  printf(bH "  cycle prog : %s" bH "               %s" bH "\n", cycleProgress.c_str(), padStr("", 15).c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN " path geometry " cRST bV2 bV2 bRTR "\n");
  printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
  printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(), pendingFav.c_str());
  printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(), maxdepthStr.c_str());
  printf(bH "  known ints : %s" bH " uniq except : %s" bH "\n", knownInts.c_str(), exceptionCount.c_str());
  printf(bH "  dictionary : %s" bH "  predicates : %s" bH "\n", dictionary.c_str(), predicateSize.c_str());
  printf(bH "       havoc : %s" bH "               %s" bH "\n", havoc.c_str(), padStr("", 5).c_str());
  printf(bH "   mutebylog : %s" bH "               %s" bH "\n", mutebylog.c_str(), padStr("", 5).c_str());
  printf(bH "      random : %s" bH "               %s" bH "\n", random.c_str(), padStr("", 5).c_str());
  printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5 bV2 bV2 bV5 bV bRTR "\n");
  printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(vulnerabilities[GASLESS_SEND]), toResult(vulnerabilities[DELEGATE_CALL]));
  printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(vulnerabilities[EXCEPTION_DISORDER]), toResult(vulnerabilities[FREEZING]));
  printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(vulnerabilities[REENTRANCY]), toResult(vulnerabilities[OVERFLOW]));
  printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(vulnerabilities[TIME_DEPENDENCY]), toResult(vulnerabilities[UNDERFLOW]));
  printf(bH " block number dependency : %s " bH "          unchecked call: %s " bH "\n", toResult(vulnerabilities[NUMBER_DEPENDENCY]), toResult(vulnerabilities[ETHER_LEAKAGE]));
  printf(bH "                suicidal : %s " bH "%s" bH "\n", toResult(vulnerabilities[SELFDESTRUCT]), padStr(" ", 32).c_str());
  printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}


// Function to write coverage and vulnerabilities info to a JSON file
void Fuzzer::writeCoverageInfo(const std::string& contractName, 
                               const std::unordered_set<std::string>& tracebits, 
                               const std::vector<bool>& vulnerabilities, 
                               uint64_t totalPaths) {
    // Create the coverage directory if it does not exist
    std::string coverageDir = "coverage";
    if (!boost::filesystem::exists(coverageDir)) {
        boost::filesystem::create_directory(coverageDir);
    }
    

    auto coverage = (uint64_t)((float) tracebits.size() / (float) totalPaths * 100);
    
    // JSON object to store coverage and vulnerabilities information
    Json::Value root;
    root["contract"] = contractName;
    root["covered_paths"] = static_cast<Json::UInt64>(tracebits.size());
    root["total_paths"] = static_cast<Json::UInt64>(totalPaths);
    root["state_functions_size"] = static_cast<Json::UInt64>(stateFdsSize);
    root["coverage"] = static_cast<Json::UInt64>(coverage);
    root["total_execs"] = static_cast<Json::UInt64>(fuzzStat.totalExecs);

    // Vulnerability names corresponding to the `vulnerabilities` vector
    std::vector<std::string> vulnerabilityNames = {
        "gasless_send", 
        "exception_disorder", 
        "time_dependency", 
        "number_dependency", 
        "delegate_call", 
        "reentrancy", 
        "freezing", 
        "underflow", 
        "overflow",
        "unchecked_call",
        "suicidal",
    };

    // Create a JSON object for vulnerabilities with "Yes" or "No" results
    Json::Value vulnerabilitiesJson;
    for (size_t i = 0; i < vulnerabilities.size(); ++i) {
        vulnerabilitiesJson[vulnerabilityNames[i]] = vulnerabilities[i] ? "Yes" : "No";
    }
    root["vulnerabilities"] = vulnerabilitiesJson;

    // Create the filename based on the contract name
    std::string filename = coverageDir + "/" + contractName + "_coverage.json";

    // Write the JSON object to the file
    std::ofstream file(filename);
    if (file.is_open()) {
        Json::StreamWriterBuilder writer;
        file << Json::writeString(writer, root);
        file.close();
    } else {
        std::cerr << "Failed to write coverage info to " << filename << std::endl;
    }
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
  auto revisedData = ContractABI::postprocessTestData(data);
  FuzzItem item(revisedData);
  item.res = te.exec(revisedData, validJumpis);
  //std::cout << "the input data right now is :" << revisedData << std::endl;
  //std::cout << "log:" << item.res.log << std::endl;
  //Logger::debug(Logger::testFormat(item.data));
  fuzzStat.totalExecs ++;
  for (auto tracebit: item.res.tracebits) {
    if (!tracebits.count(tracebit)) {
      newBranchCoverd = true;
      // Remove leader
      auto lIt = find_if(leaders.begin(), leaders.end(), [=](const pair<string, Leader>& p) { return p.first == tracebit;});
      if (lIt != leaders.end()) {
        leaders.erase(lIt);
        // Remove tracebit from queues as well if it exists
        auto qIt = find_if(queues.begin(), queues.end(), [=](const string &s) { return s == tracebit; });
        if (qIt != queues.end()) queues.erase(qIt); // Erase from queues
      }
      // Insert leader
      item.depth = depth + 1;
      auto leader = Leader(item, 0);
      leaders.insert(make_pair(tracebit, leader));
      queues.push_back(tracebit);
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();
    }
  }
  for (auto predicateIt: item.res.predicates) {
    auto lIt = find_if(leaders.begin(), leaders.end(), [=](const pair<string, Leader>& p) { return p.first == predicateIt.first;});
    if (
        lIt != leaders.end() // Found Leader
        && lIt->second.comparisonValue > 0 // Not a covered branch
        && lIt->second.comparisonValue > predicateIt.second // ComparisonValue is better
    ) {
      leaders.erase(lIt); // Remove leader
      item.depth = depth + 1;
      auto leader = Leader(item, predicateIt.second);
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();
      Logger::debug(Logger::testFormat(item.data));
    } else if (lIt == leaders.end()) {
      auto leader = Leader(item, predicateIt.second);
      item.depth = depth + 1;
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      queues.push_back(predicateIt.first);
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();

    }
  }
  updateExceptions(item.res.uniqExceptions);
  updateTracebits(item.res.tracebits);
  updatePredicates(item.res.predicates);
  return item;
}


/* Stop fuzzing */
void Fuzzer::stop() {
  Logger::debug("== TEST ==");
  unordered_map<uint64_t, uint64_t> brs;
  for (auto it : leaders) {
    auto pc = stoi(splitString(it.first, ':')[0]);
    // Covered
    if (it.second.comparisonValue == 0) {
      if (brs.find(pc) == brs.end()) {
        brs[pc] = 1;
      } else {
        brs[pc] += 1;
      }
    }
    Logger::debug("BR " + it.first);
    Logger::debug("ComparisonValue " + it.second.comparisonValue.str());
    Logger::debug(Logger::testFormat(it.second.item.data));
  }
  Logger::debug("== END TEST ==");
  for (auto it : snippets) {
    if (brs.find(it.first) == brs.end()) {
      Logger::info(">> Unreachable");
      Logger::info(it.second);
    } else {
      if (brs[it.first] == 1) {
        Logger::info(">> Haft");
        Logger::info(it.second);
      } else {
        Logger::info(">> Full");
        Logger::info(it.second);
      }
    }
  }
  exit(1);
}

/* Start fuzzing */
void Fuzzer::start() {
  auto mutatebylog_num = 20;
  TargetContainer container;
  Dictionary codeDict, addressDict;
  unordered_set<u64> showSet;
  //clear logger file content
  Logger::clearLogs();
  for (auto contractInfo : fuzzParam.contractInfo) {
    auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
    if (!contractInfo.isMain && !isAttacker) continue;
    ContractABI ca(contractInfo.abiJson);
    auto bin = fromHex(contractInfo.bin);
    auto binRuntime = fromHex(contractInfo.binRuntime);
    // Accept only valid jumpis
    if (!contractInfo.isMain) {
      /* Load Attacker agent contract */
      auto executive = container.loadContract(bin, ca);
      //ca.reorderFunctions(fuzzParam.filepath);
      auto data = ca.randomTestcase(fuzzParam.filepath);
      auto revisedData = ContractABI::postprocessTestData(data);
      executive.deploy(revisedData, EMPTY_ONOP);
      
      addressDict.fromAddress(executive.addr.asBytes());
    } else {
      auto contractName = fuzzParam.contractName;
      
      std::cout << "now is processing " <<contractName << std::endl;
      
      boost::filesystem::remove_all(contractName);
      //boost::filesystem::create_directory(contractName);
      codeDict.fromCode(bin);
      auto bytecodeBranch = BytecodeBranch(contractInfo);
      auto validJumpis = bytecodeBranch.findValidJumpis();
      snippets = bytecodeBranch.snippets;
      if (!(get<0>(validJumpis).size() + get<1>(validJumpis).size())) {
        cout << "No valid jumpi" << endl;
        stop();
      }
      
      //在这里生成所有的函数执行顺序并进行小范围测试和打分
      
      int numFunctions = ca.originalFds.size();

      if (numFunctions<=5){
        std::cout <<"state functions less than 5!" <<std::endl;
        stop();
      }
      
      stateFdsSize = ca.originalFds.size();
      
      auto executive = container.loadContract(bin, ca);
      double start = timer.elapsed();
      generateExecutionOrders(fuzzParam.filepath,validJumpis,codeDict, addressDict,executive,container);
      double end = timer.elapsed();
      totalTestTime = end-start;
      averageScore = calculateAverageScore();

      std::vector<std::string> optimalOrder = findHighestScoreOrder();
      executive.ca.setExecutionOrder(optimalOrder);
      fuzzStat.currentOrder = optimalOrder;
      
      std::string currentOrder = executive.ca.getCurrentExecutionOrder();
      std::cout <<"current execution order is:" << currentOrder <<std::endl;
      //ca.reorderFunctions(fuzzParam.filepath);
      
      saveIfInterest(executive, executive.ca.randomTestcase(fuzzParam.filepath), 0, validJumpis);
      int originHitCount = leaders.size();
      // No branch
      if (!originHitCount) {
        cout << "No branch" << endl;
        stop();
      }
      // There are uncovered branches or not
      auto fi = [&](const pair<string, Leader> &p) { return p.second.comparisonValue != 0;};
      auto numUncoveredBranches = count_if(leaders.begin(), leaders.end(), fi);
      if (!numUncoveredBranches) {
        auto curItem = (*leaders.begin()).second.item;
        Mutation mutation(curItem, make_tuple(codeDict, addressDict),executive,fuzzParam.contractName);
        mutateInfo = mutation.mutateInfo;
        vulnerabilities = container.analyze();
        switch (fuzzParam.reporter) {
          case TERMINAL: {
            showStats(mutation, validJumpis);
            break;
          }
          case JSON: {
            //writeStats(mutation,validJumpis);
            break;
          }
          case BOTH: {
            showStats(mutation, validJumpis);
            //writeStats(mutation,validJumpis);
            break;
          }
        }
        std::cout << "!numUncoveredBranches" << std::endl;
        stop();
      }
      
      // Jump to fuzz loop
      while (true) {
        auto leaderIt = leaders.find(queues[fuzzStat.idx]);
        auto curItem = leaderIt->second.item;
        auto comparisonValue = leaderIt->second.comparisonValue;
        if (comparisonValue != 0) {
          Logger::debug(" == Leader ==");
          Logger::debug("Branch \t\t\t\t " + leaderIt->first);
          Logger::debug("Comp \t\t\t\t " + comparisonValue.str());
          Logger::debug("Fuzzed \t\t\t\t " + to_string(curItem.fuzzedCount));
          Logger::debug(Logger::testFormat(curItem.data));
        }
        Mutation mutation(curItem, make_tuple(codeDict, addressDict),executive,fuzzParam.contractName);
        mutation.mutateInfo = mutateInfo;
        
        vulnerabilities = container.analyze();
        
        
        auto save = [&](bytes data) {
          auto item = saveIfInterest(executive, data, curItem.depth, validJumpis);
          /* Show every one second */
          static u64 lastEvaluationTime = totalTestTime;
          static u64 lastShowstatsTime = 0;
          int duration = timer.elapsed();
          double duration1 = timer.elapsed();
          //writestats every seconds
          if (!showSet.count(duration)) {
            showSet.insert(duration);
            vulnerabilities = container.analyze();
            switch (fuzzParam.reporter) {
            case TERMINAL: {
              //showStats(mutation, validJumpis);
              break;
            }
            case JSON: {
              auto totalPaths = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;
              //writeStats(mutation,validJumpis);
              //writeCoverageInfo(contractName, tracebits, vulnerabilities, totalPaths);
              break;
            }
            case BOTH: {
              //showStats(mutation, validJumpis);
              auto totalPaths = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;

              //writeStats(mutation,validJumpis);
              //writeCoverageInfo(contractName, tracebits, vulnerabilities, totalPaths);
              break;
            }
          }
          }
          //showstats every showstatTime period
          if (duration - lastShowstatsTime >= showStatTime) {
            lastShowstatsTime = duration;
            vulnerabilities = container.analyze();
            switch (fuzzParam.reporter) {
            case TERMINAL: {
              showStats(mutation, validJumpis);
              break;
            }
            case JSON: {
              //writeStats(mutation,validJumpis);
              break;
            }
            case BOTH: {
              showStats(mutation, validJumpis);
              //writeStats(mutation,validJumpis);
              break;
            }
            }
          }
          
          /* Every 5 seconds, re-evaluate and select the optimal function order */
          if (duration1 - lastEvaluationTime >= evaluateTime) {
              lastEvaluationTime = duration;
              
              evaluateAndSelectOptimalOrder(executive,container,validJumpis);
          }
          
          /* Stop program */
          //u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());
          if (timer.elapsed()-totalTestTime > fuzzParam.duration  || !predicates.size()) {
          
            vulnerabilities = container.analyze();
            
            switch(fuzzParam.reporter) {
              case TERMINAL: {
                showStats(mutation, validJumpis);
                
                break;
              }
              case JSON: {
                //(mutation,validJumpis);
                break;
              }
              case BOTH: {
                showStats(mutation, validJumpis);
                //writeStats(mutation,validJumpis);
                break;
              }
            }
            
            // 收集已覆盖路径数和总路径数
            auto totalPaths = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;
            auto coveredPaths = tracebits.size();

            // Write coverage and vulnerabilities info to JSON
            writeCoverageInfo(contractName, tracebits, vulnerabilities, totalPaths);
            stop();
          }
          
          
          
          return item;
        };
        // If it is uncovered branch
        if (comparisonValue != 0) {
          // if new branches are covered
          if (newBranchCoverd) {
            //update mutation stragegy
            Logger::debug("update mutate strategy");
            mutation.updateMutationStrategy(fuzzParam.filepath);
            mutateInfo = mutation.mutateInfo;
            Logger::debug("mutate");
            if (!curItem.fuzzedCount) {
              mutation.mutate(save,true);
            }else{
              mutation.mutate(save,false);
            }
            fuzzStat.stageFinds[STAGE_LOG] += leaders.size() - originHitCount;
            originHitCount = leaders.size();
            newBranchCoverd=false;
          }else{
          Logger::debug("mutate");
            if (!curItem.fuzzedCount) {
              mutation.mutate(save,true);
            }else{
              mutation.mutate(save,false);
            }
            fuzzStat.stageFinds[STAGE_LOG] += leaders.size() - originHitCount;
            originHitCount = leaders.size();
          }  
        }
        leaderIt->second.item.fuzzedCount += 1;
        fuzzStat.idx = (fuzzStat.idx + 1) % queues.size();
        if (fuzzStat.idx == 0) {
            fuzzStat.queueCycle++;
        }
        
        bool allZero = true; // 标记是否所有 comparisonValue 都为 0
        for (const auto& leader : leaders) {
            if (leader.second.comparisonValue != 0) {
                allZero = false; // 找到一个不为0的值
                break; // 提前退出循环，不需要检查其他
            }
        }
        
        // 如果所有 comparisonValue 都为 0，结束循环
        if (allZero) {
            std::cout << "All comparison values are 0, ending the fuzzing loop." << std::endl;
            // 收集已覆盖路径数和总路径数
            auto contractName = fuzzParam.contractName;
            auto totalPaths = (std::get<0>(validJumpis).size() + std::get<1>(validJumpis).size()) * 2;
            auto coveredPaths = tracebits.size();
    
            // Write coverage and vulnerabilities info to JSON
            writeCoverageInfo(contractName, tracebits, vulnerabilities, totalPaths);
            stop(); // 或者 return; 根据您的逻辑选择
        }
      }
    }
  }
}
