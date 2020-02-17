#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace llvm {
  class ExecutionEngine;
  class Module;

  namespace legacy {
    class PassManager;
  }
}

namespace extemp {
  namespace EXTLLVM2 {
    extern llvm::ExecutionEngine* ExecEngine;
    extern llvm::Module* M;
    extern std::vector<llvm::Module*> Ms;

    bool initLLVM();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uintptr_t getSymbolAddress(const std::string&);
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();
    bool setOptimize(const bool);
  } // EXTLLVM2
} // extemp
