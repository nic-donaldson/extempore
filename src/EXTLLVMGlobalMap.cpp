#include <EXTLLVMGlobalMap.h>

#include "BranchPrediction.h"

#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <unordered_map>

std::unordered_map<std::string, const llvm::GlobalValue *> sGlobalMap;

namespace extemp {
namespace EXTLLVM {
bool haveGlobalValue(const char *Name) {
  return sGlobalMap.count(Name) > 0;
}

    const void addFunction(const llvm::Function& function) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        function.printAsOperand(stream, false);
        auto result(sGlobalMap.insert(std::make_pair(stream.str().substr(1), &function)));
        if (!result.second) {
            result.first->second = &function;
        }
    }

    const void addGlobal(const llvm::GlobalVariable& global) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        global.printAsOperand(stream, false);
        auto result(sGlobalMap.insert(std::make_pair(stream.str().substr(1), &global)));
        if (!result.second) {
            result.first->second = &global;
        }
    }

const llvm::GlobalValue *getGlobalValue(const char *Name) {
  auto iter(sGlobalMap.find(Name));
  if (iter != sGlobalMap.end()) {
    return iter->second;
  }
  return nullptr;
}

    const llvm::GlobalVariable* getGlobalVariable(const char* Name) {
        auto val(getGlobalValue(Name));
        if (likely(val)) {
            return llvm::dyn_cast<llvm::GlobalVariable>(val);
        }
        return nullptr;
    }
} // namespace EXTLLVM
} // namespace extemp
