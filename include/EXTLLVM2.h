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
    extern llvm::legacy::PassManager* PM;
    extern llvm::legacy::PassManager* PM_NO;
    extern bool OPTIMIZE_COMPILES;
    extern extemp::EXTMutex alloc_mutex;
    extern llvm::Module* M;
    extern std::vector<llvm::Module*> Ms;
    extern llvm::SectionMemoryManager* MM;

    void initLLVM();
    void initPassManagers();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uint64_t getSymbolAddress(const std::string&);
  } // EXTLLVM2
} // extemp
