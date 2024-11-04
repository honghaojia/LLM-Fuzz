#pragma once
#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

class OracleFactory {
    MultipleFunction functions;
    SingleFunction function;

    // ������˽��©����⺯������
    bool detectGaslessSend(const SingleFunction& func);
    bool detectExceptionDisorder(const SingleFunction& func);
    bool detectTimeDependency(const SingleFunction& func);
    bool detectNumberDependency(const SingleFunction& func);
    bool detectDelegateCall(const SingleFunction& func);
    bool detectReentrancy(const SingleFunction& func);
    bool detectFreezing(const SingleFunction& func);
    bool detectUnderflow(const SingleFunction& func);
    bool detectOverflow(const SingleFunction& func);
    bool detectEtherLeakage(const SingleFunction& func);
    bool detectSelfdestruct(const SingleFunction& func);

    // ��������
    bool isExceptionInstruction(Instruction inst);

  public:
    vector<bool> vulnerabilities;
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);
    vector<bool> analyze();
};
