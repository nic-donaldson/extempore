#include <LLVMIRCompilation.h>

#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

namespace extemp {

  // LLVMIRCompile captures all the LLVM stuff we need to take a string
  // of LLVM IR and produce an LLVM Module
  LLVMIRCompilation::LLVMIRCompilation() {
  }

  std::string LLVMIRCompilation::SanitizeType(llvm::Type* Type)
{
    std::string type;
    llvm::raw_string_ostream typeStream(type);
    Type->print(typeStream);
    auto str(typeStream.str());
    std::string::size_type pos(str.find('='));
    if (pos != std::string::npos) {
        str.erase(pos - 1);
    }
    return str;
}

  std::regex LLVMIRCompilation::sGlobalSymRegex("[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize); 
  std::regex LLVMIRCompilation::sDefineSymRegex("define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize | std::regex::ECMAScript);
}
