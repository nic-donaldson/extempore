#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace llvm {
  class ExecutionEngine;
  class Module;
  class StructType;
  class TargetMachine;
}

namespace extemp {
  namespace EXTLLVM2 {
    extern llvm::ExecutionEngine* ExecEngine;

    bool initLLVM();
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();

    void runPassManager(llvm::Module* m);
    void addModule(llvm::Module* Module);

    uintptr_t getSymbolAddress(const std::string&);
    uintptr_t getFunctionAddress(const std::string&);

    bool setOptimize(const bool);
    std::vector<llvm::Module*>& getModules(); // TODO: probably shouldn't expose this

    // pass through some functions to the first module
    // don't know if these should go here but I don't want
    // to expose the whole module
    llvm::StructType* getTypeByName(const char*);
    long getNamedStructSize(llvm::StructType*);

    // pass through but to ExecEngine
    llvm::TargetMachine* getTargetMachine();
  } // EXTLLVM2
} // extemp
