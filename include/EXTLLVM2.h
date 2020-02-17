#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace llvm {
  class ExecutionEngine;
  class Module;
  class StructType;
}

namespace extemp {
  namespace EXTLLVM2 {
    extern llvm::ExecutionEngine* ExecEngine;

    bool initLLVM();
    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);
    uintptr_t getSymbolAddress(const std::string&);
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();
    bool setOptimize(const bool);
    std::vector<llvm::Module*>& getModules(); // TODO: probably shouldn't expose this

    // pass through some functions to the first module
    // don't know if these should go here but I don't want
    // to expose the whole module
    llvm::StructType* getTypeByName(const char*);
    long getNamedStructSize(llvm::StructType*);
  } // EXTLLVM2
} // extemp
