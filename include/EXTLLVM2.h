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
    extern llvm::Module* FirstModule; // TODO: why?

    bool initLLVM();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uintptr_t getSymbolAddress(const std::string&);
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();
    bool setOptimize(const bool);
    std::vector<llvm::Module*>& getModules(); // TODO: probably shouldn't expose this
  } // EXTLLVM2
} // extemp
