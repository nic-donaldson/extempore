#pragma once

#include "llvm/IR/GlobalValue.h"
#include <unordered_map>
#include <string>

extern std::unordered_map<std::string, const llvm::GlobalValue*> sGlobalMap;

namespace extemp {
  namespace EXTLLVM {
    const llvm::GlobalValue* getGlobalValue(const char* Name);
  } // EXTLLVM
} // extemp
