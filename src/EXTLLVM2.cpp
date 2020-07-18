#include "llvm/Support/Error.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Support/TargetSelect.h"

#include "llvm/ExecutionEngine/Orc/LLJIT.h"

#include <EXTLLVM2.h>
#include <EXTMutex.h>
#include <UNIV.h>

#include <vector>
#include <iostream>
#include <memory>
#include <regex>
#include <unordered_set>
#include <sstream>
#include <fstream>
#include <cstdlib>

#ifndef _WIN32
#include <dlfcn.h>
// TODO: remove this once done with tracing
#include <sys/sdt.h>
#else
#define DTRACE_PROBE(a, b) do {} while(0)
#define DTRACE_PROBE1(a, b, c) do {} while(0)
#define DTRACE_PROBE2(a, b, c, d) do {} while(0)
#endif

namespace llvm {
    class StructType;
    class TargetMachine;
    class Type;
}

namespace extemp {
namespace EXTLLVM2 {
namespace GlobalMap {

    static std::unordered_map<std::string, const llvm::GlobalValue *> sGlobalMap;

    bool haveGlobalValue(const char *Name) {
        return sGlobalMap.count(Name) > 0;
    }

    static void addFunction(const llvm::Function &function) {
        std::abort();
    }

    static void addGlobal(const llvm::GlobalVariable &global) {
        std::abort();
    }

    const llvm::GlobalValue *getGlobalValue(const std::string& name) {
        std::abort();
    }

    const llvm::GlobalVariable *getGlobalVariable(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalVariable, name.c_str());
        std::abort();
    }

    const llvm::Function *getFunction(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunction, name.c_str());
        std::abort();
    }

} // namespace GlobalMap
} // namespace EXTLLVM2
} // namespace extemp

namespace extemp {
namespace EXTLLVM2 {
    static std::unique_ptr<llvm::orc::LLJIT> TheJIT;
    static std::unique_ptr<llvm::orc::ThreadSafeContext> TheTSContext;
    static std::unique_ptr<llvm::Module> TheModule;
    static std::unique_ptr<llvm::legacy::PassManager> ThePM;
    static bool OPTIMIZE_COMPILES(true);

    bool initLLVM() {
        DTRACE_PROBE(extempore, initLLVM);
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        TheJIT = std::move(cantFail(llvm::orc::LLJITBuilder().create(), "Create LLJIT"));
        auto context = std::make_unique<llvm::LLVMContext>();
        TheTSContext = std::make_unique<llvm::orc::ThreadSafeContext>(std::move(context));
        TheModule = std::make_unique<llvm::Module>("my cool jit", *TheTSContext->getContext());
        TheModule->setDataLayout(TheJIT->getDataLayout());

        // TODO: bring back all the passes
        ThePM = std::make_unique<llvm::legacy::PassManager>();
        ThePM->add(llvm::createInstructionCombiningPass());
        ThePM->add(llvm::createReassociatePass());
        ThePM->add(llvm::createGVNPass());
        ThePM->add(llvm::createCFGSimplificationPass());

    }

    void addGlobalMapping(const char* name, uintptr_t address) {
        DTRACE_PROBE(extempore, addGlobalMapping);
        const llvm::DataLayout& DL = TheJIT->getDataLayout();
        llvm::orc::MangleAndInterner Mangle(TheJIT->getExecutionSession(), DL);

        // TODO: do we care about any of the JITEvaluatedSymbol flags?
        auto syms = llvm::orc::absoluteSymbols({{Mangle(name), llvm::JITEvaluatedSymbol(llvm::pointerToJITTargetAddress((void *)address), {})}});
        llvm::cantFail(TheJIT->getMainJITDylib().define(syms));
    }

    static void runPassManager(llvm::Module *m) {
        DTRACE_PROBE(extempore, runPassManager);
        if (OPTIMIZE_COMPILES) {
            ThePM->run(*m);
        }
        // TODO: do we still need an equivalent of PM_NO ?
    }

    static llvm::Module* addModule(std::unique_ptr<llvm::Module> Module) {
        DTRACE_PROBE(extempore, addModule);
        llvm::Module *modulePtr = Module.get();
        runPassManager(modulePtr);
        // TODO: can we avoid breaking unique_ptr semantics?
        //       here is where we would add functions and globals
        //       to a map but maybe we can avoid that
        cantFail(TheJIT->addIRModule(llvm::orc::ThreadSafeModule(std::move(Module), *TheTSContext)), "addModule definitely cannot fail");
        return modulePtr;
    }

    llvm::Module* jitCompile(const std::string& asmcode)
    {
        DTRACE_PROBE(extempore, jitCompile);

        llvm::SMDiagnostic pa;
        std::unique_ptr<llvm::Module> newModule(llvm::parseAssemblyString(asmcode, pa, *TheTSContext->getContext()));
        if (unlikely(!newModule)) {
            // std::cout << "**** CODE ****\n" << asmcode << " **** ENCODE ****" <<
            // std::endl; std::cout << pa.getMessage().str() << std::endl <<
            // pa.getLineNo() << std::endly;
            pa.print("LLVM IR", llvm::outs());
            return nullptr;
        }

        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }

        llvm::Module* modulePtr = addModule(std::move(newModule));
        return modulePtr;
    }

    std::string IRToBitcode(const std::string& ir) {
        DTRACE_PROBE(extempore, IRToBitcode);
        std::string bitcode;
        llvm::SMDiagnostic pa;
        auto mod(llvm::parseAssemblyString(ir, pa, *TheTSContext->getContext()));
        if (!mod) {
            pa.print("IRToBitcode", llvm::outs());
            std::abort();
        }
        llvm::raw_string_ostream bitstream(bitcode);
        llvm::WriteBitcodeToFile(*mod, bitstream);
        return bitcode;
    }

    void setOptimize(const bool b) {
        DTRACE_PROBE(extempore, setOptimize);
        std::abort();
    }

    void initPassManagers() {
        std::abort();
    }

    static uint64_t addGlobalMappingUnderEELock(const char* name, uintptr_t address) {
        std::abort();
    }

    void finalize() {
        DTRACE_PROBE(extempore, finalize);
    }





    uintptr_t getSymbolAddress(const std::string& name) {
        DTRACE_PROBE1(extempore, getSymbolAddress, name.c_str());
        std::abort();
    }

    uintptr_t getFunctionAddress(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionAddress, name);
        std::abort();
    }

    void* getPointerToGlobalIfAvailable(const std::string& name) {
        DTRACE_PROBE1(extempore, getPointerToGlobalIfAvailable, name.c_str());
        std::abort();
    }

    static llvm::Function* FindFunctionNamed(const std::string& name) {
        std::abort();
    }

    static llvm::GlobalVariable* FindGlobalVariableNamed(const std::string& name) {
        std::abort();
    }

    static void* getPointerToFunction(llvm::Function* function) {
        std::abort();
    }

    static std::vector<llvm::Module*>& getModules() {
        std::abort();
    }

    static llvm::StructType* getTypeByName(const std::string& name) {
        std::abort();
    }

    long getNamedStructSize(llvm::StructType* type) {
        DTRACE_PROBE(extempore, getNamedStructSize);
        std::abort();
    }

    long getNamedStructSize(const std::string& name) {
        DTRACE_PROBE(extempore, getNamedStructSize2);
        std::abort();
    }

    static llvm::TargetMachine* getTargetMachine() {
        std::abort();
    }

    /*static llvm::GenericValue runFunction(llvm::Function* func, std::vector<llvm::GenericValue> fargs) {
        std::abort();
        }*/

    const char* llvm_disassemble(const unsigned char* Code, int syntax) {
        DTRACE_PROBE(extempore, llvm_disassemble);
        std::abort();
    }

    // shims
    const std::string float_utohexstr(const std::string& floatin) {
        DTRACE_PROBE(extempore, float_utohexstr);
        llvm::APFloat apf(llvm::APFloat::IEEEsingle(), llvm::StringRef(floatin));
        auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
        return std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true);
    }

    const std::string double_utohexstr(const std::string& floatin) {
        DTRACE_PROBE(extempore, double_utohexstr);
        std::abort();
    }

    static std::unique_ptr<llvm::Module> parseAssemblyString(const std::string& s) {
        std::abort();
    }

    static uint64_t string_hash(const char *str) {
      uint64_t result(0);
      unsigned char c;
      while ((c = *(str++))) {
        result = result * 33 + uint8_t(c);
      }
      return result;
    }

    static void writeBitcodeToFile(llvm::Module* M, std::string& bitcode) {
        std::abort();
    }



    long getStructSize(const std::string& struct_type_str) {
        DTRACE_PROBE(extempore, getStructSize);
        std::abort();
    }



    static std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string& sInlineBitcode) {
        std::abort();
    }

    /*static bool parseAssemblyInto(const std::string& asmcode, llvm::Module& M, llvm::SMDiagnostic& pa) {
        std::abort();
        }*/


    // TODO: idk what to do with this function
    //       I'll think about it. it's like this just so
    //       we can have the LLVM code here and not in
    //       SchemeLLVMFFI
    llvm::Module* doTheThing(
        const std::string& declarations,
        const std::string& bitcode,
        const std::string& in_asmcode,
        const std::string& inlineDotLL)
    {
        DTRACE_PROBE(extempore, doTheThing);
        std::abort();
    }

    static bool writeBitcodeToFile2(llvm::Module* M, const std::string& filename) {
        std::abort();
    }

    static bool verifyModule(llvm::Module& M) {
        std::abort();
    }

    MutexGuard::MutexGuard()
        : _mg(false) {}

    MutexGuard::~MutexGuard() {
    }

    static std::string sanitizeType(llvm::Type *Type) {
        std::abort();
    }

    // match @symbols @like @this_123
    static const std::regex globalSymRegex(
      "[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
      std::regex::optimize);

    // match "define @sym"
    static const std::regex defineSymRegex(
      "define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
      std::regex::optimize | std::regex::ECMAScript);

    static void insertMatchingSymbols(
        const std::string &code, const std::regex &regex,
        std::unordered_set<std::string> &containingSet) {
      std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
                std::sregex_token_iterator(),
                std::inserter(containingSet, containingSet.begin()));
    }

    std::unordered_set<std::string> globalSyms(const std::string& code)
    {
        DTRACE_PROBE(extempore, globalSyms);
        std::unordered_set<std::string> syms;
        insertMatchingSymbols(code, globalSymRegex, syms);
        return syms;
    }

    std::string globalDeclaration(const std::string& sym) {
        DTRACE_PROBE(extempore, globalDeclaration);
        std::abort();
    }
    
    std::string globalDecls(
        const std::unordered_set<std::string>& syms,
        const std::unordered_set<std::string>& ignoreSyms)
    {
        DTRACE_PROBE(extempore, globalDecls1);
        std::stringstream dstream;
        for (const auto& sym : syms) {
            if (ignoreSyms.count(sym) == 1) {
                continue;
            }
            dstream << globalDeclaration(sym);
        }
        return dstream.str();
    }

    std::string globalDecls(
        const std::string &asmcode,
        const std::unordered_set<std::string> &sInlineSyms)
    {
        DTRACE_PROBE(extempore, globalDecls2);
        // find all symbols
        std::unordered_set<std::string> symbols;
        insertMatchingSymbols(asmcode, globalSymRegex, symbols);

        // ignore any that were defined
        // and any that are in sInlineSyms
        std::unordered_set<std::string> ignoreSymbols;
        insertMatchingSymbols(asmcode, defineSymRegex, ignoreSymbols);
        std::copy(sInlineSyms.begin(),
                  sInlineSyms.end(),
                  std::inserter(ignoreSymbols, ignoreSymbols.begin()));

        // and return a string declaring all of them
        // the idea is that any symbols that weren't defined
        // need to be declared and we assume they exist
        // somewhere
        return globalDecls(symbols, ignoreSymbols);
    }



    static char tmp_str_a[1024];
    static char tmp_str_b[4096];
    const std::vector<std::string> getFunctionArgs(const std::string& fname) {
        DTRACE_PROBE1(extempore, getFunctionArgs, fname.c_str());
        std::abort();
    }

    // no std::optional :( we'll use empty string as falsey
    const std::string getFunctionType(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionType, name.c_str());
        std::abort();
    }

    // just assuming that -1 is not a valid calling convention :|
    long long getFunctionCallingConv(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionCallingConv, name.c_str());
        std::abort();
    }

    const std::string getGlobalVariableType(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalVariableType, name.c_str());
        std::abort();
    }

    bool removeFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionByName, name.c_str());
        std::abort();
    }

    bool removeGlobalVarByName(const std::string& name) {
        DTRACE_PROBE1(extempore, removeGlobalVarByName, name.c_str());
        std::abort();
    }

    bool eraseFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, eraseFunctionByName, name.c_str());
        std::abort();
    }

    // TODO fix up return type, callers can just cast
    //      for the moment
    void* findVoidFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, findVoidFunctionByName, name.c_str());
        std::abort();
    }

    Result callCompiled(void *func_ptr, unsigned lgth, std::vector<EARG>& args) {
        DTRACE_PROBE2(extempore, callCompiled, func_ptr, lgth);
        std::abort();
    }

    void printAllModules() {
        DTRACE_PROBE(extempore, printAllModules);
        std::abort();
    }

    void printLLVMFunction(const std::string& fname) {
        DTRACE_PROBE1(extempore, printLLVMFunction, fname.c_str());
        std::abort();
    }

    void printAllClosures(const std::string& rgx) {
        DTRACE_PROBE(extempore, printAllClosures);
        std::abort();
    }

    void printClosure(const std::string& fname) {
        DTRACE_PROBE1(extempore, printClosure, fname.c_str());
        std::abort();
    }

    const char* closureLastName(const std::string& rgx) {
        DTRACE_PROBE(extempore, closureLastName);
        std::abort();
    }

    bool bindSymbol(const std::string& sym, void* library) {
        DTRACE_PROBE(extempore, bindSymbol);
        std::abort();
    }

    void* updateMapping(const std::string& sym, void* ptr) {
        DTRACE_PROBE(extempore, updateMapping);
        std::abort();
    }

    const std::string getNamedType(const std::string& name) {
        DTRACE_PROBE1(extempore, getNamedType, name.c_str());
        std::abort();
    }

    bool exportLLVMModuleBitcode(void* module, const std::string& filename) {
        DTRACE_PROBE(extempore, exportLLVMModuleBitcode);
        std::abort();
    }

    bool getFunctionVarargsByName(const std::string& fname) {
        DTRACE_PROBE1(extempore, getFunctionVaragsByName, fname.c_str());
        std::abort();
    }

    std::string getProcessTriple() {
        std::abort();
    }

} // namespace EXTLLVM2
} // namespace extemp
