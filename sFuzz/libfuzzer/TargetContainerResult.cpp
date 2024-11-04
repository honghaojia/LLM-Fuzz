#include "TargetContainerResult.h"

namespace fuzzer {

  TargetContainerResult::TargetContainerResult(
    unordered_set<string> tracebits,
    unordered_map<string, u256> predicates,
    unordered_set<string> uniqExceptions,
    string cksum,
    string log
  ) {
    this->tracebits = tracebits;
    this->cksum = cksum;
    this->predicates = predicates;
    this->uniqExceptions = uniqExceptions;
    this->log = log;
  }
}
