#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <unordered_set>

namespace llvm {
  class Module;
  class Function;
  class GlobalVariable;
  class GlobalValue;
  class MutexGuard;
}

namespace extemp {
namespace EXTLLVM2 {
namespace GlobalMap {
  const llvm::GlobalVariable* getGlobalVariable(const std::string& name);
  const llvm::Function* getFunction(const std::string& name);
}
}
}

namespace extemp {
  namespace EXTLLVM2 {
    // returns true if initialization was performed, doesn't necessarily indicate
    // success. call this more than once and it should return false.
    bool initLLVM();
    void addGlobalMapping(const char*, uintptr_t);
    void finalize();

    uintptr_t getSymbolAddress(const std::string&);
    uintptr_t getFunctionAddress(const std::string&);
    void* getPointerToGlobalIfAvailable(const std::string&);

    void setOptimize(const bool);

    // pass through some functions to the first module
    // don't know if these should go here but I don't want
    // to expose the whole module
    long getNamedStructSize(const std::string& name);
    long getStructSize(const std::string& struct_type_str);

    // this doesn't feel like it belongs here too much
    const char* llvm_disassemble(const unsigned char*, int);

    // shims
    const std::string float_utohexstr(const std::string&);
    const std::string double_utohexstr(const std::string&);

    std::string IRToBitcode(const std::string& ir);
    llvm::Module* doTheThing(
        const std::string& declarations,
        const std::string& bitcode,
        const std::string& in_asmcode,
        const std::string& inlineDotLL);

    class MutexGuard {
    public:
      MutexGuard();
      ~MutexGuard();

    private:
      llvm::MutexGuard* _mg;
    };

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
    void* findVoidFunctionByName(const std::string& name);

    enum class ArgType {
      INT = 0,
      DOUBLE = 1,
      STRING = 2,
      PTR = 3,
      NOTHING = 4
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
    bool exportLLVMModuleBitcode(void* module, const std::string& filename);
    bool getFunctionVarargsByName(const std::string& fname);

  } // EXTLLVM2
} // extemp
