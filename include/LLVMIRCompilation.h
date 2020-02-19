#pragma once

#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <regex>
#include <unordered_set>

namespace extemp {
class LLVMIRCompilation {
public:
  LLVMIRCompilation();
  ~LLVMIRCompilation() = default;
  std::string
  necessaryGlobalDeclarations(const std::string &asmcode,
                              const std::unordered_set<std::string> &sInlineSyms);

  static void
  insertMatchingSymbols(const std::string &code, const std::regex &regex,
                        std::unordered_set<std::string> &containingSet);

  static std::string SanitizeType(llvm::Type *Type);
  static const std::regex sGlobalSymRegex;
  static const std::regex sDefineSymRegex;

private:
};
} // namespace extemp
