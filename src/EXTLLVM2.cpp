// If EXTLLVM was so good why didn't they make an EXTLLVM2?
#include "llvm/AsmParser/Parser.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/MutexGuard.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"

// if you remove this it segfaults for some reason?
// if you look at the header it does some kind of magic so
// maybe that's not unexpected
#include "llvm/ExecutionEngine/MCJIT.h"

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


#ifndef _WIN32
#include <dlfcn.h>
// TODO: remove this once done with tracing
#include <sys/sdt.h>
#else
#define DTRACE_PROBE(a, b) do {} while(0)
#define DTRACE_PROBE1(a, b, c) do {} while(0)
#define DTRACE_PROBE2(a, b, c, d) do {} while(0)
#endif

namespace extemp {
namespace EXTLLVM2 {
namespace GlobalMap {

    static std::unordered_map<std::string, const llvm::GlobalValue *> sGlobalMap;

    bool haveGlobalValue(const char *Name) {
        return sGlobalMap.count(Name) > 0;
    }

    static void addFunction(const llvm::Function &function) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        function.printAsOperand(stream, false);
        auto result(
                    sGlobalMap.insert(std::make_pair(stream.str().substr(1), &function)));
        if (!result.second) {
            result.first->second = &function;
        }
    }

    static void addGlobal(const llvm::GlobalVariable &global) {
        std::string str;
        llvm::raw_string_ostream stream(str);
        global.printAsOperand(stream, false);
        auto result(
                    sGlobalMap.insert(std::make_pair(stream.str().substr(1), &global)));
        if (!result.second) {
            result.first->second = &global;
        }
    }

    const llvm::GlobalValue *getGlobalValue(const std::string& name) {
        auto iter(sGlobalMap.find(name));
        if (iter != sGlobalMap.end()) {
            return iter->second;
        }
        return nullptr;
    }

    const llvm::GlobalVariable *getGlobalVariable(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalVariable, name.c_str());
        auto val(getGlobalValue(name));
        if (likely(val)) {
            return llvm::dyn_cast<llvm::GlobalVariable>(val);
        }
        return nullptr;
    }

    const llvm::Function *getFunction(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunction, name.c_str());
        auto val(getGlobalValue(name));
        if (likely(val)) {
            return llvm::dyn_cast<llvm::Function>(val);
        }
        return nullptr;
    }

} // namespace GlobalMap
} // namespace EXTLLVM2
} // namespace extemp

namespace extemp {
namespace EXTLLVM2 {
    static bool OPTIMIZE_COMPILES = true;
    static llvm::ExecutionEngine* ExecEngine = nullptr;
    static llvm::legacy::PassManager* PM = nullptr;
    static llvm::legacy::PassManager* PM_NO = nullptr;
    static llvm::Module* FirstModule = nullptr;
    static std::vector<llvm::Module*> Modules;
    static llvm::SectionMemoryManager* MM = nullptr;

    void setOptimize(const bool b) {
        DTRACE_PROBE(extempore, setOptimize);
        OPTIMIZE_COMPILES = b;
    }

    void initPassManagers() {
        PM_NO = new llvm::legacy::PassManager();
        PM_NO->add(llvm::createAlwaysInlinerPass());

        PM = new llvm::legacy::PassManager();
        PM->add(llvm::createAggressiveDCEPass());
        PM->add(llvm::createAlwaysInlinerPass());
        PM->add(llvm::createArgumentPromotionPass());
        PM->add(llvm::createCFGSimplificationPass());
        PM->add(llvm::createDeadStoreEliminationPass());
        PM->add(llvm::createFunctionInliningPass());
        PM->add(llvm::createGVNPass(true));
        PM->add(llvm::createIndVarSimplifyPass());
        PM->add(llvm::createInstructionCombiningPass());
        PM->add(llvm::createJumpThreadingPass());
        PM->add(llvm::createLICMPass());
        PM->add(llvm::createLoopDeletionPass());
        PM->add(llvm::createLoopRotatePass());
        PM->add(llvm::createLoopUnrollPass());
        PM->add(llvm::createMemCpyOptPass());
        PM->add(llvm::createPromoteMemoryToRegisterPass());
        PM->add(llvm::createReassociatePass());
        PM->add(llvm::createScalarReplAggregatesPass());
        PM->add(llvm::createSCCPPass());
        PM->add(llvm::createTailCallEliminationPass());
    }

    bool initLLVM() {
        DTRACE_PROBE(extempore, initLLVM);
        if (ExecEngine) {
            return false;
        }

        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        LLVMInitializeX86Disassembler();

        auto& context(llvm::getGlobalContext());
        auto module(llvm::make_unique<llvm::Module>("xtmmodule_0", context));
        FirstModule = module.get();

        for (const auto& function : FirstModule->getFunctionList()) {
            GlobalMap::addFunction(function);
        }
        for (const auto& global : FirstModule->getGlobalList()) {
            GlobalMap::addGlobal(global);
        }
        Modules.push_back(FirstModule);

        if (!extemp::UNIV::ARCH.empty()) {
            FirstModule->setTargetTriple(extemp::UNIV::ARCH);
        }

        // Build engine with JIT
        llvm::EngineBuilder factory(std::move(module));
        factory.setEngineKind(llvm::EngineKind::JIT);

        llvm::TargetOptions Opts;
        Opts.GuaranteedTailCallOpt = true;
        Opts.UnsafeFPMath = false;
        factory.setTargetOptions(Opts);

        auto memoryManager(llvm::make_unique<llvm::SectionMemoryManager>());
        MM = memoryManager.get();
        factory.setMCJITMemoryManager(std::move(memoryManager));

#ifdef _WIN32
        bool windows = true;
#else
        bool windows = false;
#endif

        llvm::TargetMachine* tm = nullptr;
        if (windows) {
            if (!extemp::UNIV::ATTRS.empty()) {
                factory.setMAttrs(extemp::UNIV::ATTRS);
            }
            if (!extemp::UNIV::CPU.empty()) {
                factory.setMCPU(extemp::UNIV::CPU);
            }
            tm = factory.selectTarget();
        } else {
            factory.setOptLevel(llvm::CodeGenOpt::Aggressive);
            llvm::Triple triple(llvm::sys::getProcessTriple());
            std::string cpu;
            if (!extemp::UNIV::CPU.empty()) {
                cpu = extemp::UNIV::CPU.front();
            } else {
                cpu = llvm::sys::getHostCPUName();
            }
            llvm::SmallVector<std::string, 10> lattrs;
            if (!extemp::UNIV::ATTRS.empty()) {
                for (const auto &attr : extemp::UNIV::ATTRS) {
                    lattrs.append(1, attr);
                }
            } else {
                llvm::StringMap<bool> HostFeatures;
                llvm::sys::getHostCPUFeatures(HostFeatures);
                for (auto &feature : HostFeatures) {
                    std::string featureName = feature.getKey().str();
                    // temporarily disable all AVX512-related codegen because it
                    // causes crashes on this old version of LLVM - see GH #378
                    // for more details.
                    if (feature.getValue() && featureName.compare(0, 6, "avx512")) {
                        lattrs.append(1, featureName);
                    } else {
                        lattrs.append(1, std::string("-") + featureName);
                    }
                }
            }
            tm = factory.selectTarget(triple, "", cpu, lattrs);
        }
        ExecEngine = factory.create(tm);

        ExecEngine->DisableLazyCompilation(true);
        ascii_normal();
        std::cout << "ARCH           : " << std::flush;
        ascii_info();
        std::cout << std::string(tm->getTargetTriple().normalize()) << std::endl;

        bool windows_check = windows && !std::string(tm->getTargetFeatureString()).empty();
        bool not_windows_check = !windows && !std::string(tm->getTargetCPU()).empty();
        if (windows_check || not_windows_check) {
            ascii_normal();
            std::cout << "CPU            : " << std::flush;
            ascii_info();
            std::cout << std::string(tm->getTargetCPU()) << std::endl;
        }
        if (!std::string(tm->getTargetFeatureString()).empty()) {
            ascii_normal();
            std::cout << "ATTRS          : " << std::flush;
            auto data(tm->getTargetFeatureString().data());
            for (; *data; ++data) {
                switch (*data) {
                case '+':
                    ascii_info();
                    break;
                case '-':
                    ascii_error();
                    break;
                case ',':
                    ascii_normal();
                    break;
                }
                putchar(*data);
            }
            putchar('\n');
        }
        ascii_normal();
        std::cout << "LLVM           : " << std::flush;
        ascii_info();
        std::cout << LLVM_VERSION_STRING;
        std::cout << " MCJIT" << std::endl;
        ascii_normal();
        initPassManagers();
        return true;
    }

    void addGlobalMapping(const char* name, uintptr_t address) {
        DTRACE_PROBE(extempore, addGlobalMapping);
        ExecEngine->updateGlobalMapping(name, address);
    }

    static uint64_t addGlobalMappingUnderEELock(const char* name, uintptr_t address) {
        llvm::MutexGuard locked(ExecEngine->lock);
        // returns previous value of the mapping, or NULL if not set
        return ExecEngine->updateGlobalMapping(name, address);
    }

    void finalize() {
        DTRACE_PROBE(extempore, finalize);
        ExecEngine->finalizeObject();
    }

    static void runPassManager(llvm::Module *m) {
        assert(PM);
        assert(PM_NO);

        if (OPTIMIZE_COMPILES) {
            PM->run(*m);
        } else {
            PM_NO->run(*m);
        }
    }

    static llvm::Module* addModule(std::unique_ptr<llvm::Module> Module) {
        llvm::Module *modulePtr = Module.get();
        runPassManager(modulePtr);
        ExecEngine->addModule(std::move(Module));
        ExecEngine->finalizeObject();
        if (modulePtr) {
            for (const auto& function : modulePtr->getFunctionList()) {
                GlobalMap::addFunction(function);
            }
            for (const auto& global : modulePtr->getGlobalList()) {
                GlobalMap::addGlobal(global);
            }
            Modules.push_back(modulePtr);
        }
        return modulePtr;
    }

    uintptr_t getSymbolAddress(const std::string& name) {
        auto addr(MM->getSymbolAddress(name));
        DTRACE_PROBE2(extempore, getSymbolAddress, name.c_str(), addr);
        return addr;
    }

    uintptr_t getFunctionAddress(const std::string& name) {
        auto addr(ExecEngine->getFunctionAddress(name));
        DTRACE_PROBE2(extempore, getFunctionAddress, name, addr);
        return addr;
    }

    void* getPointerToGlobalIfAvailable(const std::string& name) {
        auto ptr(ExecEngine->getPointerToGlobalIfAvailable(name));
        DTRACE_PROBE2(extempore, getPointerToGlobalIfAvailable, name.c_str(), ptr);
        return ExecEngine->getPointerToGlobalIfAvailable(name);
    }

    static llvm::Function* FindFunctionNamed(const std::string& name) {
        return ExecEngine->FindFunctionNamed(name.c_str());
    }

    static llvm::GlobalVariable* FindGlobalVariableNamed(const std::string& name) {
        return ExecEngine->FindGlobalVariableNamed(name.c_str());
    }

    static void* getPointerToFunction(llvm::Function* function) {

        return ExecEngine->getPointerToFunction(function);
    }

    static std::vector<llvm::Module*>& getModules() {
        return Modules;
    }

    static llvm::StructType* getTypeByName(const std::string& name) {
        return FirstModule->getTypeByName(name.c_str());
    }

    long getNamedStructSize(llvm::StructType* type) {
        DTRACE_PROBE(extempore, getNamedStructSize);
        auto layout(new llvm::DataLayout(FirstModule));
        long size = layout->getStructLayout(type)->getSizeInBytes();
        delete layout;
        return size;
    }

    long getNamedStructSize(const std::string& name) {
        auto type(getTypeByName(name));
        if (!type) {
            return -1;
        }
        return getNamedStructSize(name);
    }

    static llvm::TargetMachine* getTargetMachine() {
        return ExecEngine->getTargetMachine();
    }

    static llvm::GenericValue runFunction(llvm::Function* func, std::vector<llvm::GenericValue> fargs) {
        return ExecEngine->runFunction(func, fargs);
    }

    const char* llvm_disassemble(const unsigned char* Code, int syntax) {
        DTRACE_PROBE(extempore, llvm_disassemble);
        size_t code_size = 1024 * 100;
        std::string Error;
        llvm::TargetMachine *TM = getTargetMachine();
        llvm::Triple Triple = TM->getTargetTriple();
        const llvm::Target TheTarget = TM->getTarget();
        std::string TripleName = Triple.getTriple();
        // const llvm::Target* TheTarget =
        // llvm::TargetRegistry::lookupTarget(ArchName,Triple,Error);
        const llvm::MCRegisterInfo *MRI(TheTarget.createMCRegInfo(TripleName));
        const llvm::MCAsmInfo *AsmInfo(
            TheTarget.createMCAsmInfo(*MRI, TripleName));
        const llvm::MCSubtargetInfo *STI(
            TheTarget.createMCSubtargetInfo(TripleName, "", ""));
        const llvm::MCInstrInfo *MII(TheTarget.createMCInstrInfo());
        // const llvm::MCInstrAnalysis*
        // MIA(TheTarget->createMCInstrAnalysis(MII->get()));
        llvm::MCContext Ctx(AsmInfo, MRI, nullptr);
        llvm::MCDisassembler *DisAsm(TheTarget.createMCDisassembler(*STI, Ctx));
        llvm::MCInstPrinter *IP(TheTarget.createMCInstPrinter(
            Triple, syntax, *AsmInfo, *MII, *MRI)); //,*STI));
        IP->setPrintImmHex(true);
        IP->setUseMarkup(true);
        std::string out_str;
        llvm::raw_string_ostream OS(out_str);
        llvm::ArrayRef<uint8_t> mem(Code, code_size);
        uint64_t size;
        uint64_t index;
        OS << "\n";
        for (index = 0; index < code_size; index += size) {
            llvm::MCInst Inst;
            if (DisAsm->getInstruction(Inst, size, mem.slice(index), index,
                                       llvm::nulls(), llvm::nulls())) {
                auto instSize(*reinterpret_cast<const size_t*>(Code + index));
                if (instSize <= 0) {
                    break;
                }
                OS.indent(4);
                OS.write("0x", 2);
                OS.write_hex(size_t(Code) + index);
                OS.write(": ", 2);
                OS.write_hex(instSize);
                IP->printInst(&Inst, OS, "", *STI);
                OS << "\n";
            } else if (!size) {
                size = 1;
            }
        }
        return strdup(OS.str().c_str());
    }

    // shims
    const std::string float_utohexstr(const std::string& floatin) {
        DTRACE_PROBE(extempore, float_utohexstr);
        llvm::APFloat apf(llvm::APFloat::IEEEsingle, llvm::StringRef(floatin));
        auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
        return std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true);
    }

    const std::string double_utohexstr(const std::string& floatin) {
        DTRACE_PROBE(extempore, double_utohexstr);
        llvm::APFloat apf(llvm::APFloat::IEEEdouble, llvm::StringRef(floatin));
        // TODO: if necessary, checks for inf/nan can be done here
        auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
        return std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true);
    }

    static std::unique_ptr<llvm::Module> parseAssemblyString(const std::string& s) {
        llvm::SMDiagnostic pa;
        std::unique_ptr<llvm::Module> mod(llvm::parseAssemblyString(s, pa, llvm::getGlobalContext()));
        if (!mod) {
            std::cout << pa.getMessage().str() << std::endl;
            abort();
        }
        return mod;
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
        llvm::raw_string_ostream bitstream(bitcode);
        llvm::WriteBitcodeToFile(M, bitstream);
    }

    std::string IRToBitcode(const std::string& ir) {
        DTRACE_PROBE(extempore, IRToBitcode);
        std::string bitcode;
        auto mod(parseAssemblyString(ir));
        writeBitcodeToFile(mod.get(), bitcode);
        return bitcode;
    }

    long getStructSize(const std::string& struct_type_str) {
        DTRACE_PROBE(extempore, getStructSize);
        unsigned long long hash = string_hash(struct_type_str.c_str());
        char name[128];
        sprintf(name, "_xtmT%lld", hash);
        char assm[1024];
        sprintf(assm, "%%%s = type %s", name, struct_type_str.c_str());

        llvm::SMDiagnostic pa;
        auto newM(llvm::parseAssemblyString(assm, pa, llvm::getGlobalContext()));
        if (!newM) {
            return -1;
        }
        auto type(newM->getTypeByName(name));
        if (!type) {
            return -1;
        }
        auto layout(new llvm::DataLayout(newM.get()));
        long size = layout->getStructLayout(type)->getSizeInBytes();
        delete layout;
        return size;
    }



    static std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string& sInlineBitcode) {
        llvm::ErrorOr<std::unique_ptr<llvm::Module>> maybe(llvm::parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"),
                                          llvm::getGlobalContext()));
        if (maybe) {
            return std::move(maybe.get());
        } else {
            return nullptr;
        }
    }

    static bool parseAssemblyInto(const std::string& asmcode, llvm::Module& M, llvm::SMDiagnostic& pa) {
        return llvm::parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), M, pa);
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
        std::string asmcode(in_asmcode);
        std::unique_ptr<llvm::Module> newModule(parseBitcodeFile(bitcode));
        llvm::SMDiagnostic pa;

        if (likely(newModule)) {
            asmcode = inlineDotLL + declarations + asmcode;
            if (parseAssemblyInto(asmcode, *newModule, pa)) {
                std::cout << "**** DECL ****"
                          << std::endl
                          << declarations
                          << "**** ENDDECL ****"
                          << std::endl;
                newModule.reset();
            }
        }

        if (unlikely(!newModule)) {
            pa.print("LLVM IR", llvm::outs());
            return nullptr;
        }

        if (verifyModule(*newModule)) {
            std::cout << "Invalid LLVM IR" << std::endl;
            return nullptr;
        }

        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }

        llvm::Module *modulePtr = addModule(std::move(newModule));

        DTRACE_PROBE1(extempore, doTheThing, modulePtr);
        return modulePtr;
    }

    static bool writeBitcodeToFile2(llvm::Module* M, const std::string& filename) {
        std::error_code errcode;
        llvm::raw_fd_ostream ss(filename, errcode, llvm::sys::fs::F_RW);
        if (errcode) {
            std::cout << errcode.message() << std::endl;
            return false;
        }
        llvm::WriteBitcodeToFile(M, ss);
        return true;
    }

    static bool verifyModule(llvm::Module& M) {
        return llvm::verifyModule(M);
    }

    MutexGuard::MutexGuard()
        : _mg(new llvm::MutexGuard(ExecEngine->lock)) {}

    MutexGuard::~MutexGuard() {
        delete _mg;
    }

    static std::string sanitizeType(llvm::Type *Type) {
        std::string type;
        llvm::raw_string_ostream typeStream(type);
        Type->print(typeStream);
        auto str(typeStream.str());
        std::string::size_type pos(str.find('='));
        if (pos != std::string::npos) {
            str.erase(pos - 1);
        }
        return str;
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
        const llvm::Value* gv =
            GlobalMap::getGlobalValue(sym.c_str());

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
            for (const auto& arg : func->getArgumentList()) {
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

    llvm::Module* jitCompile(const std::string& asmcode)
    {
        DTRACE_PROBE(extempore, jitCompile);
        llvm::SMDiagnostic pa;
        std::unique_ptr<llvm::Module> newModule(llvm::parseAssemblyString(asmcode, pa, llvm::getGlobalContext()));

        if (unlikely(!newModule)) {
            // std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" <<
            // std::endl; std::cout << pa.getMessage().str() << std::endl <<
            // pa.getLineNo() << std::endl;
            pa.print("LLVM IR", llvm::outs());
            return nullptr;
        }

        if (verifyModule(*newModule)) {
            std::cout << "Invalid LLVM IR" << std::endl;
            return nullptr;
        }

        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }

        llvm::Module* modulePtr = addModule(std::move(newModule));
        return modulePtr;
    }

    static char tmp_str_a[1024];
    static char tmp_str_b[4096];
    const std::vector<std::string> getFunctionArgs(const std::string& fname) {
        DTRACE_PROBE1(extempore, getFunctionArgs, fname.c_str());
        std::vector<std::string> res;

        auto func(GlobalMap::getFunction(fname));
        if (!func) {
            return res;
        }

        std::string typestr;
        llvm::raw_string_ostream ss(typestr);

        func->getReturnType()->print(ss);
        const char* tmp_name = ss.str().c_str();
        const char* eq_type_string = " = type ";

        if (func->getReturnType()->isStructTy()) {
            rsplit(eq_type_string, tmp_name, tmp_str_a, tmp_str_b);
            tmp_name = tmp_str_a;
        }
        res.push_back(tmp_name);

        for (const auto& arg : func->getArgumentList()) {
            std::string typestr2;
            llvm::raw_string_ostream ss2(typestr2);
            arg.getType()->print(ss2);
            tmp_name = ss2.str().c_str();
            if (arg.getType()->isStructTy()) {
                rsplit(eq_type_string, tmp_name, tmp_str_a, tmp_str_b);
                tmp_name = tmp_str_a;
            }
            res.push_back(tmp_name);
        }

        return res;

    }

    // no std::optional :( we'll use empty string as falsey
    const std::string getFunctionType(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionType, name.c_str());
        auto func(GlobalMap::getFunction(name));
        if (!func) {
            return "";
        }

        std::string typestr;
        llvm::raw_string_ostream ss(typestr);
        func->getFunctionType()->print(ss);
        return typestr;
    }

    // just assuming that -1 is not a valid calling convention :|
    long long getFunctionCallingConv(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionCallingConv, name.c_str());
        auto func(GlobalMap::getFunction(name));
        if (!func) {
            return -1;
        }
        return func->getCallingConv();
    }

    const std::string getGlobalVariableType(const std::string& name) {
        DTRACE_PROBE1(extempore, getGlobalVariableType, name.c_str());
        std::string res;
        auto var(GlobalMap::getGlobalVariable(name));
        if (!var) {
            return res;
        }

        llvm::raw_string_ostream ss(res);
        var->getType()->print(ss);
        return ss.str();
    }

    bool removeFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, getFunctionByName, name.c_str());
        auto func(FindFunctionNamed(name));
        if (!func) {
            return false;
        }
        if (func->mayBeOverridden()) {
            func->dropAllReferences();
            func->removeFromParent();
            return true;
        }
        printf("Cannot remove function with dependencies\n");
        return false;
    }

    bool removeGlobalVarByName(const std::string& name) {
        DTRACE_PROBE1(extempore, removeGlobalVarByName, name.c_str());
        auto var(EXTLLVM2::FindGlobalVariableNamed(name));
        if (!var) {
            return false;
        }
        var->dropAllReferences();
        var->removeFromParent();
        return true;
    }

    bool eraseFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, eraseFunctionByName, name.c_str());
        auto func(FindFunctionNamed(name));
        if (!func) {
            return false;
        }
        DTRACE_PROBE2(extempore, eraseFunctionByName, name.c_str(), func);
        func->dropAllReferences();
        func->removeFromParent();
        //func->deleteBody();
        //func->eraseFromParent();
        return true;
    }

    // TODO fix up return type, callers can just cast
    //      for the moment
    void* findVoidFunctionByName(const std::string& name) {
        DTRACE_PROBE1(extempore, findVoidFunctionByName, name.c_str());
        auto func(FindFunctionNamed(name));
        if (!func) {
            return 0;
        }
        return getPointerToFunction(func);
    }

    Result callCompiled(void *func_ptr, unsigned lgth, std::vector<EARG>& args) {
        DTRACE_PROBE2(extempore, callCompiled, func_ptr, lgth);
        auto func(reinterpret_cast<llvm::Function *>(func_ptr));
        if (unlikely(!func)) {
            printf("No such function\n");
            return {ResultType::BAD, {}};
        }

        if (unlikely(lgth != func->getArgumentList().size())) {
            printf("Wrong number of arguments for function!\n");
            return {ResultType::BAD, {}};
        }

        // this code seems to be broken??
        // i is never incremented.
        // seems also lgth is never ever greater than 0 so
        // maybe we're all g here

        int i = 0;
        std::vector<llvm::GenericValue> fargs;
        fargs.reserve(lgth);

        for (const auto &arg : func->getArgumentList()) {
            EARG p = args.back();
            args.pop_back();

            if (p.tag == ArgType::INT) {
                if (unlikely(arg.getType()->getTypeID() != llvm::Type::IntegerTyID)) {
                    printf("Bad argument type %i\n", i);
                    return {ResultType::BAD, {}};
                }
                int width = arg.getType()->getPrimitiveSizeInBits();
                fargs[i].IntVal = llvm::APInt(width, p.int_val);
            } else if (p.tag == ArgType::DOUBLE) {
                if (arg.getType()->getTypeID() == llvm::Type::FloatTyID) {
                    fargs[i].FloatVal = p.double_val;
                } else if (arg.getType()->getTypeID() == llvm::Type::DoubleTyID) {
                    fargs[i].DoubleVal = p.double_val;
                } else {
                    printf("Bad argument type %i\n", i);
                    return {ResultType::BAD, {}};
                }
            } else if (p.tag == ArgType::STRING) {
                if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                    printf("Bad argument type %i\n", i);
                    return {ResultType::BAD, {}};
                }
                fargs[i].PointerVal = p.string;
            } else if (p.tag == ArgType::PTR) {
                if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                    printf("Bad argument type %i\n", i);
                    return {ResultType::BAD, {}};
                }
                fargs[i].PointerVal = p.ptr;
            } else {
                printf("Bad argement at index %in\n", i);
                return {ResultType::BAD, {}};
            }
        }

        llvm::GenericValue gv = runFunction(func, fargs);
        EARG res;
        switch (func->getReturnType()->getTypeID()) {
        case llvm::Type::FloatTyID:
            res.tag = ArgType::DOUBLE;
            res.double_val = gv.FloatVal;
            break;
        case llvm::Type::DoubleTyID:
            res.tag = ArgType::DOUBLE;
            res.double_val = gv.DoubleVal;
            break;
        case llvm::Type::IntegerTyID:
            res.tag = ArgType::INT;
            res.int_val = gv.IntVal.getZExtValue();
            break;
        case llvm::Type::PointerTyID:
            res.tag = ArgType::PTR;
            res.ptr = gv.PointerVal;
            break;
        case llvm::Type::VoidTyID:
            res.tag = ArgType::NOTHING;
            break;
        default:
            return {ResultType::BAD, {}};
        }
        return {ResultType::GOOD, res};
    }

    void printAllModules() {
        DTRACE_PROBE(extempore, printAllModules);
        for (auto module : getModules()) {
            std::string str;
            llvm::raw_string_ostream ss(str);
            ss << *module;
            printf("\n---------------------------------------------------\n%s", ss.str().c_str());
        }
    }

    void printLLVMFunction(const std::string& fname) {
        DTRACE_PROBE1(extempore, printLLVMFunction, fname.c_str());
        auto func(GlobalMap::getFunction(fname.c_str()));
        if (!func) {
            return;
        }
        std::string str;
        llvm::raw_string_ostream ss(str);
        ss << *func;
        puts(ss.str().c_str());
    }

    void printAllClosures(const std::string& rgx) {
        DTRACE_PROBE(extempore, printAllClosures);
        for (auto module : getModules()) {
            for (const auto& func : module->getFunctionList()) {
                if (func.hasName() && rmatch(rgx.c_str(), func.getName().data())) {
                    std::string str;
                    llvm::raw_string_ostream ss(str);
                    ss << func;
                    printf("\n---------------------------------------------------\n%s", ss.str().c_str());
                }
            }
        }
    }

    void printClosure(const std::string& fname) {
        DTRACE_PROBE1(extempore, printClosure, fname.c_str());
        for (auto module : getModules()) {
            for (const auto& func : module->getFunctionList()) {
                if (func.hasName() && !strcmp(func.getName().data(), fname.c_str())) {
                    std::string str;
                    llvm::raw_string_ostream ss(str);
                    ss << func;
                    if (ss.str().find_first_of("{") != std::string::npos) {
                        std::cout << str << std::endl;
                    }
                }
            }
        }
    }

    const char* closureLastName(const std::string& rgx) {
        DTRACE_PROBE(extempore, closureLastName);
        const char* last_name(nullptr);
        for (auto module : getModules()) {
            for (const auto& func : module->getFunctionList()) {
                if (func.hasName() && rmatch(rgx.c_str(), func.getName().data())) {
                    last_name = func.getName().data();
                }
            }
        }
        return last_name;
    }

    bool bindSymbol(const std::string& sym, void* library) {
        DTRACE_PROBE(extempore, bindSymbol);
        #ifdef _WIN32
        auto ptr(reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(library), sym.c_str())));
        #else
        auto ptr(dlsym(library, sym.c_str()));
        #endif
        if (likely(ptr)) {
            addGlobalMappingUnderEELock(sym.c_str(), reinterpret_cast<uint64_t>(ptr));
            return true;
        }
        return false;
    }

    void* updateMapping(const std::string& sym, void* ptr) {
        DTRACE_PROBE(extempore, updateMapping);
        auto oldval(addGlobalMappingUnderEELock(sym.c_str(), reinterpret_cast<uintptr_t>(ptr)));
        return reinterpret_cast<void*>(oldval);
    }

    const std::string getNamedType(const std::string& name) {
        DTRACE_PROBE1(extempore, getNamedType, name.c_str());
        int ptrDepth = 0;
        int len(name.length() - 1);
        while (len >= 0 && name[len--] == '*') {
            ++ptrDepth;
        }
        auto tt(getTypeByName(std::string(name, len)));
        if (tt) {
            std::string typestr;
            llvm::raw_string_ostream ss(typestr);
            tt->print(ss);
            auto tmp_name = ss.str().c_str();
            if (tt->isStructTy()) {
                rsplit(" = type ", tmp_name, tmp_str_a, tmp_str_b);
                tmp_name = tmp_str_b;
            }
            return (std::string(tmp_str_b) + std::string(ptrDepth, '*')).c_str();
        }
        return "";
    }

    bool exportLLVMModuleBitcode(void* module, const std::string& filename) {
        DTRACE_PROBE(extempore, exportLLVMModuleBitcode);
        auto m(reinterpret_cast<llvm::Module*>(module));
        if (!m) {
            return false;
        }
        #ifdef _WIN32
        std::string str;
        std::ofstream fout(filename);
        llvm::raw_string_ostream ss(str);
        ss << *m;
        std::string irStr = ss.str();
        // add dllimport (otherwise global variables won't work)
        std::string oldStr(" external global ");
        std::string newStr(" external dllimport global ");
        size_t pos = 0;
        while ((pos = irStr.find(oldStr, pos)) != std::string::npos) {
            irStr.replace(pos, oldStr.length(), newStr);
            pos += newStr.length();
        }
        // LLVM can't handle guaranteed tail call under win64 yet
        oldStr = std::string(" tail call ");
        newStr = std::string(" call ");
        pos = 0;
        while ((pos = irStr.find(oldStr, pos)) != std::string::npos) {
          irStr.replace(pos, oldStr.length(), newStr);
          pos += newStr.length();
        }
        fout << irStr; // ss.str();
        fout.close();
        #else
        if (!writeBitcodeToFile2(m, filename)) {
            return false;
        }
        #endif
        return true;
    }

    bool getFunctionVarargsByName(const std::string& fname) {
        DTRACE_PROBE1(extempore, getFunctionVaragsByName, fname.c_str());
        auto func(GlobalMap::getFunction(fname.c_str()));
        return (func && func->isVarArg());
    }


} // namespace EXTLLVM2
} // namespace extemp
