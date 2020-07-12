#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <regex>
#include <unordered_set>

namespace llvm {
  class ExecutionEngine;
  class Module;
  class StructType;
  class TargetMachine;
  class Function;
  class GlobalVariable;
  class GlobalValue;
  class GenericValue;
  class SMDiagnostic;
  class MutexGuard;
  class Type;
}

namespace extemp {
namespace EXTLLVM2 {
  namespace GlobalMap {
    bool haveGlobalValue(const char* Name);
    const llvm::GlobalValue* getGlobalValue(const char* Name);
    const llvm::GlobalVariable* getGlobalVariable(const char* Name);
    const llvm::Function* getFunction(const char* Name);
    void addFunction(const llvm::Function& function);
    void addGlobal(const llvm::GlobalVariable& global);
  }
}
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
    llvm::StructType* getTypeByName(const std::string&);
    long getNamedStructSize(const std::string& name);
    long getStructSize(const std::string& struct_type_str);

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

    std::string sanitizeType(llvm::Type *Type);

    extern const std::regex globalSymRegex;
    extern const std::regex defineSymRegex;

    void insertMatchingSymbols(
      const std::string &code, const std::regex &regex,
      std::unordered_set<std::string> &containingSet);

    std::unordered_set<std::string> globalSyms(const std::string& code);

    std::string globalDecls(
      const std::string &asmcode,
      const std::unordered_set<std::string> &sInlineSyms);

    llvm::Module* jitCompile(const std::string&);

    const std::vector<std::string> getFunctionArgs(const std::string& fname);
    const std::string getFunctionType(const std::string& name);
    long long getFunctionCallingConv(const std::string& name);
    const std::string getGlobalVariableType(const std::string& name);
    bool removeFunctionByName(const std::string& name);
    bool removeGlobalVarByName(const std::string& name);
    bool eraseFunctionByName(const std::string& name);
    void * findVoidFunctionByName(const std::string& name);

    enum class ArgType {
      INT = 0,
      DOUBLE = 1,
      STRING = 2,
      PTR = 3,
      VOID = 4
    };
    struct EARG {
      ArgType tag;
      union {
          int64_t int_val;
          double double_val;
          char* string;
          void* ptr;
      };
    };

    enum class ResultType {
      BAD = 0,
      GOOD = 1
    };
    struct Result {
      ResultType tag;
      EARG val;
    };

    Result callCompiled(void *func_ptr, unsigned lgth, std::vector<EARG>& args);
    void printAllModules();
    void printLLVMFunction(const std::string& fname);
    void printAllClosures(const std::string& rgx);
    void printClosure(const std::string& fname);
    const char* closureLastName(const std::string& rgx);
    bool bindSymbol(const std::string& sym, void* library);
    void* updateMapping(const std::string& sym, void* ptr);
    const std::string getNamedType(const std::string& name);

  } // EXTLLVM2
} // extemp
