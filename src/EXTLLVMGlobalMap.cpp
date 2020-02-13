#include "llvm/IR/GlobalValue.h"
#include <unordered_map>
#include <string>
#include <EXTLLVMGlobalMap.h>

std::unordered_map<std::string, const llvm::GlobalValue*> sGlobalMap;

namespace extemp {
namespace EXTLLVM {
const llvm::GlobalValue* getGlobalValue(const char* Name)
{
    auto iter(sGlobalMap.find(Name));
    if (iter != sGlobalMap.end()) {
        return iter->second;
    }
    return nullptr;
}
} // EXTLLVM
} // extemp
