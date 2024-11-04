#pragma once
#include <vector>
#include "Common.h"
#include "LLMhelper.h"

using namespace dev;
using namespace std;

namespace fuzzer {
  using Accounts = vector<tuple<bytes, u160, u256, bool>>;
  using FakeBlock = tuple<bytes, int64_t, int64_t>;
  
  struct DataType {
    bytes value;
    bool padLeft;
    bool isDynamic;
    DataType(){};
    DataType(bytes value, bool padLeft, bool isDynamic);
    bytes payload();
    bytes header();
  };
  
  struct TypeDef {
    string paraname;
    string name;
    string fullname;
    string realname;
    bool padLeft;
    bool isDynamic;
    bool isDynamicArray;
    bool isSubDynamicArray;
    TypeDef(string name,string paraname);
    void addValue(bytes v);
    void addValue(vector<bytes> vs);
    void addValue(vector<vector<bytes>> vss);
    static string toFullname(string name);
    static string toRealname(string name);
    vector<int> extractDimension(string name);
    vector<int> dimensions;
    DataType dt;
    vector<DataType> dts;
    vector<vector<DataType>> dtss;
  };
  
  struct FuncDef {
    string name;
    bool payable;
    vector<TypeDef> tds;
    FuncDef(){};
    FuncDef(string name, vector<TypeDef> tds, bool payable);
  };
  
  struct EventDef {
    string name;
    vector<TypeDef> tds;

    EventDef(string _name, vector<TypeDef> _parameters) 
        : name(_name), tds(_parameters) {};
    };
  
  class ContractABI {
    vector<bytes> accounts;
    bytes block;
    std::unordered_map<std::string,int> functionPriorityMap;
    public:
      vector<FuncDef> fds;
      vector<FuncDef> originalFds;
      vector<EventDef> events;
      std::unordered_map<std::string, std::string> eventHashToSignatureMap;
      ContractABI(){};
      ContractABI(string abiJson);
      /* encoded ABI of contract constructor */
      bytes encodeConstructor();
      /* encoded ABI of contract functions */
      vector<bytes> encodeFunctions();
      /* Create random testcase for fuzzer */
      bytes randomTestcase(std::string filepath);
      /* Update then call encodeConstructor/encodeFunction to feed to evm */
      void updateTestData(bytes data);
      //generate new function orders
      void reorderFunctions(std::string filepath);
      void setExecutionOrder(const std::vector<std::string>& order);
      std::string generateFunctionAPIs(std::string contractName);
      std::string executionOrder();
      /* Standard Json */
      string toStandardJson();
      uint64_t totalFuncs();
      Accounts decodeAccounts();
      FakeBlock decodeBlock();
      std::string functionapi(std::string name, std::vector<TypeDef> tds);
      std::vector<uint8_t> hexStringToBytes(const std::string& hex);
      bool isPayable(string name);
      Address getSender();
      static bytes encodeTuple(vector<TypeDef> tds);
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
      static bytes functionSelector(string name, vector<TypeDef> tds);
      static bytes eventSelector(string name, vector<TypeDef> tds);
      static bytes postprocessTestData(bytes data);
      std::pair<bool, std::vector<std::string>> isValidOrder(const std::vector<std::string>& order);
      std::string getCurrentExecutionOrder() const;
  };
}
