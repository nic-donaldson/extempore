#pragma once

#include <unordered_map>
#include <string>

namespace llvm {
    class GlobalVariable;
    class GlobalValue;
    class Function;
}

namespace extemp {
namespace EXTLLVM {
  namespace GlobalMap {
    bool haveGlobalValue(const char* Name);
    const llvm::GlobalValue* getGlobalValue(const char* Name);
    const llvm::GlobalVariable* getGlobalVariable(const char* Name);
    const llvm::Function* getFunction(const char* Name);
    const void addFunction(const llvm::Function& function);
    const void addGlobal(const llvm::GlobalVariable& global);
  } // GlobalMap
} // EXTLLVM
} // extemp
