#include <EXTLLVMGlobalMap.h>
#include <LLVMIRCompilation.h>

#include <iostream>

int main(int argc, char **argv) {
  if (sGlobalMap.count("hello") == 1) {
    return 1;
  }

  {
    std::unordered_set<std::string> expected_syms{"hello", "$123", "____quux"};
    std::unordered_set<std::string> syms;
    extemp::LLVMIRCompilation::insertMatchingSymbols(" @hello @42 @$123 @____quux", extemp::LLVMIRCompilation::sGlobalSymRegex, syms);
    if (expected_syms != syms) {
      std::cerr << "syms contains:" << std::endl;
      for (const auto& sym : syms) {
        std::cerr << sym << ", ";
      }
      std::cerr << std::endl;
      return 1;
    }
  }

  return 0;
}
