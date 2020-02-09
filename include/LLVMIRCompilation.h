#pragma once

#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <regex>

namespace extemp {
  class LLVMIRCompilation {
  public:
    LLVMIRCompilation();
    ~LLVMIRCompilation() = default;

    static std::string SanitizeType(llvm::Type* Type);
    static std::regex sGlobalSymRegex;
    static std::regex sDefineSymRegex;
  private:
  };
} // extemp
