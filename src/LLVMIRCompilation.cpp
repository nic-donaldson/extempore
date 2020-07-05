#include <LLVMIRCompilation.h>
#include <EXTLLVMGlobalMap.h>
#include <EXTLLVM2.h>

#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <list>
#include <regex>
#include <string>
#include <iterator>
#include <sstream>

namespace extemp {

  // LLVMIRCompile captures all the LLVM stuff we need to take a string
  // of LLVM IR and produce an LLVM Module
  // or at least that's a long term goal?
  LLVMIRCompilation::LLVMIRCompilation() {
  }

  // match @symbols @like @this_123
  const std::regex LLVMIRCompilation::globalSymRegex(
    "[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
    std::regex::optimize);

  // match "define @sym"
  const std::regex LLVMIRCompilation::defineSymRegex(
    "define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
    std::regex::optimize | std::regex::ECMAScript);

  void LLVMIRCompilation::insertMatchingSymbols(const std::string& code, const std::regex& regex, std::unordered_set<std::string>& containingSet)
  {
      std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
                std::sregex_token_iterator(), std::inserter(containingSet, containingSet.begin()));
  }

  std::string LLVMIRCompilation::necessaryGlobalDeclarations(const std::string& asmcode, const std::unordered_set<std::string>& sInlineSyms)
  {
    std::unordered_set<std::string> symbols;
    insertMatchingSymbols(asmcode, globalSymRegex, symbols);

    std::unordered_set<std::string> definedSyms;
    insertMatchingSymbols(asmcode, defineSymRegex, definedSyms);

    std::stringstream dstream;
    for (const auto& sym : symbols) {
        // if the symbol from asmcode is present in inline.ll/bitcode.ll
        // don't redeclare it as they'll be included in the module
        if (sInlineSyms.count(sym) == 1) {
            continue;
        }

        if (definedSyms.count(sym) == 1) {
            continue;
        }

        const llvm::Value* gv = extemp::EXTLLVM::GlobalMap::getGlobalValue(sym.c_str());
        if (!gv) {
            continue;
        }

        const llvm::Function* func(llvm::dyn_cast<llvm::Function>(gv));
        if (func) {
            dstream << "declare "
                    << extemp::EXTLLVM2::sanitizeType(func->getReturnType())
                    << " @"
                    << sym
                    << " (";

            bool first(true);
            for (const auto& arg : func->getArgumentList()) {
                if (!first) {
                    dstream << ", ";
                } else {
                    first = false;
                }
                dstream << extemp::EXTLLVM2::sanitizeType(arg.getType());
            }

            if (func->isVarArg()) {
                dstream << ", ...";
            }
            dstream << ")\n";
        } else {
            auto str(extemp::EXTLLVM2::sanitizeType(gv->getType()));
            dstream << '@' << sym << " = external global " << str.substr(0, str.length() - 1) << '\n';
        }
    }
    return dstream.str();
  }


}
