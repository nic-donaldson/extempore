#include "llvm/Support/Error.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Support/TargetSelect.h"

#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
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
#endif

#ifdef TRACING
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
    static std::unordered_map<std::string, llvm::Type *> sHMM;
    static std::unordered_map<std::string, llvm::FunctionType *> sHMM2;
    static std::unordered_map<std::string, std::unique_ptr<Fn>> sFunctionMap;
    static std::unordered_map<std::string, std::string> sTypeMap;

    static void addHMM(const llvm::GlobalVariable& gv) {
        sHMM.insert_or_assign(gv.getName(), gv.getType());
    }

    static void addHMM2(const llvm::Function& f) {
        sHMM2.insert_or_assign(f.getName(), f.getFunctionType());
    }

    static llvm::Type* getHMM(const std::string& name) {
        auto iter(sHMM.find(name));
        if (iter != sHMM.end()) {
            return iter->second;
        }
        return nullptr;
    }

    static llvm::FunctionType* getHMM2(const std::string& name) {
        auto iter(sHMM2.find(name));
        if (iter != sHMM2.end()) {
            return iter->second;
        }
        return nullptr;
    }

    bool haveGlobalValue(const char *Name) {
        return sGlobalMap.count(Name) > 0;
    }

    static ArgType argTypeFromLLVMType(const llvm::Type::TypeID& llvm_type) {
        switch (llvm_type) {
        case llvm::Type::IntegerTyID:
            return ArgType::INT;
        case llvm::Type::FloatTyID:
        case llvm::Type::DoubleTyID:
            return ArgType::DOUBLE;
        case llvm::Type::PointerTyID:
            return ArgType::PTR;
        case llvm::Type::VoidTyID:
            return ArgType::NOTHING;
        default:
            std::cout << "Don't know how to handle arg type" << std::endl;
            // TODO: not this
            return ArgType::PTR;
        }
    }

    // TODO: can we at least try not to leak memory?
    static std::unique_ptr<Fn> newFunction(const llvm::Function &function) {
        auto f = std::make_unique<Fn>();

        std::string str;
        llvm::raw_string_ostream stream(str);
        function.printAsOperand(stream, false);
        f->sym = stream.str().substr(1);

        f->args.reserve(function.arg_size());
        for (const auto &arg : function.args()) {
            //arg.getType()->print(llvm::outs());
            //llvm::outs().write('\n');
            f->args.push_back(argTypeFromLLVMType(arg.getType()->getTypeID()));
        }
        //function.getReturnType()->print(llvm::outs());
        //llvm::outs().write('\n');
        f->ret = argTypeFromLLVMType(function.getReturnType()->getTypeID());
        return f;
    }


    static void addFunction(const llvm::Function &function) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        function.printAsOperand(stream, false);
        auto result(sGlobalMap.insert(std::make_pair(stream.str().substr(1), &function)));
        if (!result.second) {
            result.first->second = &function;
        }
    }
    
    static void addFunction2(const llvm::Function &function) {
        auto f = newFunction(function);
        sFunctionMap.insert_or_assign(f->sym, std::move(f));
        addFunction(function);
    }

    static void addGlobal(const llvm::GlobalVariable &global) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        global.printAsOperand(stream, false);
        auto result(sGlobalMap.insert(std::make_pair(stream.str().substr(1), &global)));
        if (!result.second) {
            result.first->second = &global;
        }
    }

    const llvm::GlobalVariable *getGlobalVariable(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalVariable, name.c_str());
        std::abort();
    }

    const llvm::GlobalValue *getGlobalValue(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalValue, name.c_str());
        auto iter(sGlobalMap.find(name));
        if (iter != sGlobalMap.end()) {
            return iter->second;
        }
        DTRACE_PROBE(extempore, getGlobalValueNull);
        return nullptr;
    }

    const llvm::Function *getFunctionOld(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunction, name.c_str());
        auto val(getGlobalValue(name));
        if (likely(val)) {
            return llvm::dyn_cast<llvm::Function>(val);
        }
        DTRACE_PROBE(extempore, getFunctionNull);
        return nullptr;
    }

    // TODO: use a shared_ptr?
    const Fn* getFunction(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunction, name.c_str());
        auto iter(sFunctionMap.find(name));
        if (iter != sFunctionMap.end()) {
            // TODO: this is bad
            return iter->second.get();
        }
        return nullptr;
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

        TheJIT = cantFail(llvm::orc::LLJITBuilder().create(), "Create LLJIT");

        // add process symbols (sorta)
        // TODO: why does this not work? :(
        auto dlsrg = llvm::cantFail(llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(TheJIT->getDataLayout().getGlobalPrefix()), "DynamicLibrarySearchGenerator");
        TheJIT->getMainJITDylib().addGenerator(std::move(dlsrg));

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

        // TODO: this
        return true;
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

        if (modulePtr) {
            for (const auto& function : modulePtr->getFunctionList()) {
                GlobalMap::addFunction2(function);
                GlobalMap::addHMM2(function);
            }
            for (const auto& global : modulePtr->getGlobalList()) {
                GlobalMap::addGlobal(global);
                GlobalMap::addHMM(global);
            }
        }


        cantFail(TheJIT->addIRModule(llvm::orc::ThreadSafeModule(std::move(Module), *TheTSContext)), "addModule definitely cannot fail");
        if (modulePtr) {
            // for (const auto& function : modulePtr->getFunctionList()) {
            //     GlobalMap::addFunction(function);
            // }
            // for (const auto& global : modulePtr->getGlobalList()) {
            //     GlobalMap::addGlobal(global);
            // }
        }
        // todo: bring back `Modules`?
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

    static std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string& sInlineBitcode)
    {
        // TODO: don't use cantFail
        auto maybe(cantFail(llvm::parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), *TheTSContext->getContext()), "parseBitcodeFile"));

        return maybe;
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

        if (in_asmcode.find("%String") != std::string::npos) {
            asm("nop");
        }

        // TODO: not this
        //       anything but this
        std::unordered_set<std::string> defines;
        insertMatchingSymbols(in_asmcode, defineSymRegex, defines);
        for (const auto& sym : defines) {
            eraseFunctionByName(sym);
        }
        //

        // TODO: :(
        std::stringstream typess;
        for (const auto& pair : GlobalMap::sTypeMap) {
            typess << pair.second;
            typess << std::endl;
        }
        const std::string types = typess.str();
        //

        // TODO: another gross hack
        // also TODO: learn how to use std::regex and not this capture group thing
        static std::regex literallyJustATypeDefinition("(%.*? = type.*$)");
        std::unordered_set<std::string> typeDefines;
        insertMatchingSymbols(in_asmcode, literallyJustATypeDefinition, typeDefines);
        for (const auto& sym : typeDefines) {
            auto eq_index = sym.find("=");
            GlobalMap::sTypeMap.insert_or_assign(sym.substr(0, eq_index - 1), sym);
        }
        //

        std::string asmcode(in_asmcode);
        std::unique_ptr<llvm::Module> newModule(parseBitcodeFile(bitcode));
        std::unique_ptr<llvm::ModuleSummaryIndex> msi(cantFail(llvm::getModuleSummaryIndex(llvm::MemoryBufferRef(bitcode, "<string>")), "ModuleSummaryIndex"));
        llvm::SMDiagnostic pa;

        if (likely(newModule)) {
            asmcode = inlineDotLL + types + declarations + asmcode;
            if (llvm::parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), newModule.get(), msi.get(), pa)) {
                std::cout << "inlineDotLL:"
                          << std::endl
                          << inlineDotLL
                          << std::endl
                          << "types:"
                          << std::endl
                          << types
                          << std::endl
                          << "declarations:"
                          << std::endl
                          << declarations
                          << "asmcode:"
                          << std::endl
                          << asmcode
                          << std::endl;
                newModule.reset();
            }
        }

        if (unlikely(!newModule)) {
            pa.print("LLVM IR", llvm::outs());
            std::abort();
            return nullptr;
        }

        if (llvm::verifyModule(*newModule)) {
            std::cout << "Invalid LLVM IR" << std::endl;
            return nullptr;
        }

        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }

        // :(
        llvm::Module *modulePtr = addModule(std::move(newModule));

        return modulePtr;
    }

    bool eraseFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, eraseFunctionByName, name.c_str());
        if (name == "xtlang_expression_adhoc_W2k4Kl0_setter") {
            asm("nop");
        }
        
        // use that jitdylib hack :|
        // TODO: revisit this with new ORC stuff in LLVM11/12
        auto& main = TheJIT->getMainJITDylib();
        auto sym = TheJIT->lookup(name);
        if (sym) {
            auto& ES = TheJIT->getExecutionSession();
            cantFail(main.remove({ES.intern(name)}), "removing something");
            return true;
        }
        return false;
    }

    void setOptimize(const bool b) {
        DTRACE_PROBE(extempore, setOptimize);
        std::cout << "setOptimize does nothing" << std::endl;
        //std::abort();
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
        auto sym = TheJIT->lookup(name);
        if (sym) {
            return static_cast<uintptr_t>(sym.get().getAddress());
        } else {
            TheJIT->getMainJITDylib().dump(llvm::outs());
            for (int i = 0; i < 20; i++) {
                std::cout << ">:(" << std::endl;
            }
            // not calling abort in case this is desired behaviour
            // std::abort();
        }
        return 0;
    }

    void* getPointerToGlobalIfAvailable(const std::string& name) {
        //TODO: is this what this function is meant to do??
        DTRACE_PROBE1(extempore, getPointerToGlobalIfAvailable, name.c_str());
        auto sym = TheJIT->lookup(name);
        if (sym) {
            return reinterpret_cast<void *>(sym.get().getAddress());
        } else {
            return nullptr;
        }
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
        DTRACE_PROBE(extempore, sanitizeType);
        std::string type;
        llvm::raw_string_ostream typeStream(type);
        Type->print(typeStream);
        auto str(typeStream.str());
        std::string::size_type pos(str.find('='));
        if (pos != std::string::npos) {
            str.erase(pos - 1);
        }

        if (str == "%mzone.18*") {
            asm("nop");
        }

        if (str.substr(0, 6) == "%mzone") {
            asm("nop");
        }

        // if type ends in .XX* where X is a number we
        // should strip the numbers, let's try this:
        std::string::size_type start(str.find('.'));
        std::string::size_type end(str.find('*'));
        if (start != std::string::npos) {
            if (end == str.length() - 1) {
                str.erase(start, (end - start));
            } else {
                str.erase(start, str.length() - start);
            }
        }
        return str;
    }



    std::unordered_set<std::string> globalSyms(const std::string& code)
    {
        DTRACE_PROBE(extempore, globalSyms);
        std::unordered_set<std::string> syms;
        insertMatchingSymbols(code, globalSymRegex, syms);
        return syms;
    }

    std::string globalDeclaration(const std::string& sym) {
        if (sym == "String_val_adhoc_W1N0cmluZyxpNjQsaTgqXQ__992") {
            asm("nop");
        }
        // TODO: this will need to handle syms in the process too
        //       or alternatively, throw them on some list when
        //       bind-ext-val gets called?
        DTRACE_PROBE1(extempore, globalDeclaration, sym.c_str());

        llvm::Type* t = GlobalMap::getHMM(sym);
        if (t) {
            auto str(sanitizeType(t));
            std::stringstream ss;
            ss << '@'
               << sym
               << " = external global "
               << str.substr(0, str.length() - 1)
               << "\n";
            return ss.str();
        }

        llvm::FunctionType* ft = GlobalMap::getHMM2(sym);
        if (ft) {
            std::stringstream ss;
            ss << "declare "
               << sanitizeType(ft->getReturnType())
               << " @" << sym << " (";

            bool first(true);
            for (const auto& arg : ft->params()) {
                if (!first) {
                    ss << ", ";
                } else {
                    first = false;
                }
                ss << sanitizeType(arg);
            }

            if (ft->isVarArg()) {
                ss << ", ...";
            }
            ss << ")\n";
            return ss.str();
        }

        const llvm::Value* gv = GlobalMap::getGlobalValue(sym.c_str());

        if (!gv) {
            return "";
        }

        std::stringstream ss;
        const llvm::Function* func(llvm::dyn_cast<llvm::Function>(gv));
        if (func) {
            ss << "declare "
               << sanitizeType(func->getReturnType())
               << " @" << sym << " (";

            bool first(true);
            for (const auto& arg : func->args()) {
                if (!first) {
                    ss << ", ";
                } else {
                    first = false;
                }
                ss << sanitizeType(arg.getType());
            }

            if (func->isVarArg()) {
                ss << ", ...";
            }
            ss << ")\n";
        } else {
            auto str(sanitizeType(gv->getType()));
            ss << '@'
               << sym
               << " = external global "
               << str.substr(0, str.length() - 1)
               << "\n";
        }
        return ss.str();
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
        DTRACE_PROBE1(extempore, removeFunctionByName, name.c_str());
        if (name == "xtlang_expression_adhoc_W2k4Kl0_setter") {
            asm("nop");
        }
        return eraseFunctionByName(name);
    }

    bool removeGlobalVarByName(const std::string& name) {
        DTRACE_PROBE1(extempore, removeGlobalVarByName, name.c_str());
        std::abort();
    }



    // TODO fix up return type, callers can just cast
    //      for the moment
    void* findVoidFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, findVoidFunctionByName, name.c_str());
        std::abort();
    }

    Result callCompiled(Fn *func_ptr, unsigned lgth, std::vector<EARG>& args) {
        DTRACE_PROBE2(extempore, callCompiled, func_ptr, lgth);
        std::cout << "someone is looking for " << func_ptr->sym << std::endl;

        if (func_ptr->args.size() == 0 && func_ptr->ret == ArgType::NOTHING) {
            void (*f)() = (void (*)())getFunctionAddress(func_ptr->sym);
            f();
        } else {
            std::cout << "nope not supported" << std::endl;
            std::abort();
        }
        std::cout << "we lived!" << std::endl;
        EARG res;
        res.tag = ArgType::NOTHING;
        return {ResultType::GOOD, res};
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
