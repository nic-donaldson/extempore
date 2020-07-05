#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace llvm {
  class ExecutionEngine;
  class Module;
  class StructType;
  class TargetMachine;
  class Function;
  class GlobalVariable;
  class GenericValue;
  class SMDiagnostic;
  class MutexGuard;
}

namespace extemp {
  namespace EXTLLVM2 {
    // returns true if initialization was performed, doesn't necessarily indicate
    // success. call this more than once and it should return false.
    bool initLLVM();
    void addGlobalMapping(const char*, uintptr_t);
    uint64_t addGlobalMappingUnderEELock(const char*, uintptr_t);
    void finalize();

    void runPassManager(llvm::Module* m);
    llvm::Module* addModule(std::unique_ptr<llvm::Module> Module);

    uintptr_t getSymbolAddress(const std::string&);
    uintptr_t getFunctionAddress(const std::string&);
    void* getPointerToGlobalIfAvailable(const std::string&);
    llvm::Function* FindFunctionNamed(const std::string&);
    llvm::GlobalVariable* FindGlobalVariableNamed(const std::string&);
    void* getPointerToFunction(llvm::Function* function);

    void setOptimize(const bool);
    std::vector<llvm::Module*>& getModules(); // TODO: probably shouldn't expose this

    // pass through some functions to the first module
    // don't know if these should go here but I don't want
    // to expose the whole module
    llvm::StructType* getTypeByName(const char*);
    long getNamedStructSize(llvm::StructType*);

    // pass through but to ExecEngine
    llvm::TargetMachine* getTargetMachine();
    // llvm::sys::Mutex& getEEMutex(); // this is annoying I hope we can lose it
    llvm::GenericValue runFunction(llvm::Function*, std::vector<llvm::GenericValue>);

    // this doesn't feel like it belongs here too much
    const char* llvm_disassemble(const unsigned char*, int);

    // shims
    const std::string float_utohexstr(const std::string&);
    const std::string double_utohexstr(const std::string&);

    std::unique_ptr<llvm::Module> parseAssemblyString(const std::string&);
    std::unique_ptr<llvm::Module> parseAssemblyString2(const std::string& s, llvm::SMDiagnostic& pa);
    std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string& sInlineBitcode);
    bool parseAssemblyInto(const std::string& asmcode, llvm::Module &M, llvm::SMDiagnostic &pa);
    void writeBitcodeToFile(llvm::Module* M, std::string& bitcode);
    bool writeBitcodeToFile2(llvm::Module* M, const std::string& filename);
    bool verifyModule(llvm::Module& M);

    class MutexGuard {
    public:
      MutexGuard();
      ~MutexGuard();

    private:
      llvm::MutexGuard* _mg;
    };

  } // EXTLLVM2
} // extemp
