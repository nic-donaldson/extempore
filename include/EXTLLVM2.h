#pragma once

#include <vector>

namespace llvm {
  class ExecutionEngine;
  class Module;

  namespace legacy {
    class PassManager;
  }
}

namespace extemp {
  namespace EXTLLVM2 {
    extern llvm::ExecutionEngine* EE;
    extern llvm::Module* M;
    extern std::vector<llvm::Module*> Ms;

    bool initLLVM();
    void initPassManagers();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uint64_t getSymbolAddress(const std::string&);
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();
    bool setOptimize(const bool);
  } // EXTLLVM2
} // extemp
