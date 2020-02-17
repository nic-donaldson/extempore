#pragma once

#include <EXTMutex.h>
#include <vector>

namespace llvm {
  class ExecutionEngine;
  class Module;
  class SectionMemoryManager;

  namespace legacy {
    class PassManager;
  }
}

namespace extemp {
  namespace EXTLLVM2 {
    extern llvm::ExecutionEngine* EE;
    extern bool OPTIMIZE_COMPILES;
    extern llvm::Module* M;
    extern std::vector<llvm::Module*> Ms;
    extern llvm::SectionMemoryManager* MM;

    bool initLLVM();
    void initPassManagers();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uint64_t getSymbolAddress(const std::string&);
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();
  } // EXTLLVM2
} // extemp
