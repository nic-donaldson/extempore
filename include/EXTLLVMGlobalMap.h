#pragma once

#include "llvm/IR/GlobalValue.h"
#include <unordered_map>
#include <string>

extern std::unordered_map<std::string, const llvm::GlobalValue*> sGlobalMap;
