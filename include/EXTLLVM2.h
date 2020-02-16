#pragma once

#include <EXTMutex.h>

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
    extern llvm::legacy::PassManager* PM;
    extern llvm::legacy::PassManager* PM_NO;
    extern bool OPTIMIZE_COMPILES;
    extern extemp::EXTMutex alloc_mutex;

    void initLLVM();
    void initPassManagers();
    void runPassManager(llvm::Module* m);
  } // EXTLLVM2
} // extemp
