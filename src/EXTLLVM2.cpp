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

#ifndef _WIN32
#include <dlfcn.h>
#endif

static std::unordered_map<std::string, const llvm::GlobalValue *> sGlobalMap;

namespace extemp {
namespace EXTLLVM2 {
namespace GlobalMap {
bool haveGlobalValue(const char *Name) { return sGlobalMap.count(Name) > 0; }

void addFunction(const llvm::Function &function) {
    std::string str;
    llvm::raw_string_ostream stream(str);
    function.printAsOperand(stream, false);
    auto result(
                sGlobalMap.insert(std::make_pair(stream.str().substr(1), &function)));
    if (!result.second) {
        result.first->second = &function;
    }
}

void addGlobal(const llvm::GlobalVariable &global) {
    std::string str;
    llvm::raw_string_ostream stream(str);
    global.printAsOperand(stream, false);
    auto result(
                sGlobalMap.insert(std::make_pair(stream.str().substr(1), &global)));
    if (!result.second) {
        result.first->second = &global;
    }
}

const llvm::GlobalValue *getGlobalValue(const char *Name) {
    auto iter(sGlobalMap.find(Name));
    if (iter != sGlobalMap.end()) {
        return iter->second;
    }
    return nullptr;
}

const llvm::GlobalVariable *getGlobalVariable(const char *Name) {
    auto val(getGlobalValue(Name));
    if (likely(val)) {
        return llvm::dyn_cast<llvm::GlobalVariable>(val);
    }
    return nullptr;
}

const llvm::Function *getFunction(const char *Name) {
    auto val(getGlobalValue(Name));
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
    bool OPTIMIZE_COMPILES = true;
    llvm::ExecutionEngine* ExecEngine = nullptr;
    llvm::legacy::PassManager* PM = nullptr;
    llvm::legacy::PassManager* PM_NO = nullptr;
    llvm::Module* FirstModule = nullptr;
    std::vector<llvm::Module*> Modules;

    // TODO: make this static once it's fully moved over
    llvm::SectionMemoryManager* MM = nullptr;

    void setOptimize(const bool b) {
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

    // just a name we give this for the moment
    // this function probably shouldn't exist
    void onetwothree(llvm::Module* Module);

    bool initLLVM() {
        if (ExecEngine) {
            return false;
        }

        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        LLVMInitializeX86Disassembler();

        auto& context(llvm::getGlobalContext());
        auto module(llvm::make_unique<llvm::Module>("xtmmodule_0", context));
        FirstModule = module.get();
        onetwothree(FirstModule);
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
        ExecEngine->updateGlobalMapping(name, address);
    }

    uint64_t addGlobalMappingUnderEELock(const char* name, uintptr_t address) {
        llvm::MutexGuard locked(ExecEngine->lock);
        // returns previous value of the mapping, or NULL if not set
        return ExecEngine->updateGlobalMapping(name, address);
    }

    void finalize() {
        ExecEngine->finalizeObject();
    }

    void runPassManager(llvm::Module *m) {
        assert(PM);
        assert(PM_NO);

        if (OPTIMIZE_COMPILES) {
            PM->run(*m);
        } else {
            PM_NO->run(*m);
        }
    }

    void onetwothree(llvm::Module* Module) {
        for (const auto& function : Module -> getFunctionList()) {
            GlobalMap::addFunction(function);
        }
        for (const auto& global : Module->getGlobalList()) {
            GlobalMap::addGlobal(global);
        }
        Modules.push_back(Module);
    }

    llvm::Module* addModule(std::unique_ptr<llvm::Module> Module) {
        llvm::Module *modulePtr = Module.get();
        runPassManager(modulePtr);
        ExecEngine->addModule(std::move(Module));
        ExecEngine->finalizeObject();
        if (modulePtr) {
            onetwothree(modulePtr);
        }
        return modulePtr;
    }

    uintptr_t getSymbolAddress(const std::string& name) {
        return MM->getSymbolAddress(name);
    }

    uintptr_t getFunctionAddress(const std::string& name) {
        return ExecEngine->getFunctionAddress(name);
    }

    void* getPointerToGlobalIfAvailable(const std::string& name) {
        return ExecEngine->getPointerToGlobalIfAvailable(name);
    }

    llvm::Function* FindFunctionNamed(const std::string& name) {
        return ExecEngine->FindFunctionNamed(name.c_str());
    }

    llvm::GlobalVariable* FindGlobalVariableNamed(const std::string& name) {
        return ExecEngine->FindGlobalVariableNamed(name.c_str());
    }

    void* getPointerToFunction(llvm::Function* function) {

        return ExecEngine->getPointerToFunction(function);
    }

    std::vector<llvm::Module*>& getModules() {
        return Modules;
    }

    llvm::StructType* getTypeByName(const std::string& name) {
        return FirstModule->getTypeByName(name.c_str());
    }

    long getNamedStructSize(llvm::StructType* type) {
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

    llvm::TargetMachine* getTargetMachine() {
        return ExecEngine->getTargetMachine();
    }

    llvm::sys::Mutex& getEEMutex() {
        return ExecEngine->lock;
    }

    llvm::GenericValue runFunction(llvm::Function* func, std::vector<llvm::GenericValue> fargs) {
        return ExecEngine->runFunction(func, fargs);
    }

    const char* llvm_disassemble(const unsigned char* Code, int syntax) {
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
        llvm::APFloat apf(llvm::APFloat::IEEEsingle, llvm::StringRef(floatin));
        auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
        return std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true);
    }
    const std::string double_utohexstr(const std::string& floatin) {
        llvm::APFloat apf(llvm::APFloat::IEEEdouble, llvm::StringRef(floatin));
        // TODO: if necessary, checks for inf/nan can be done here
        auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
        return std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true);
    }

    std::unique_ptr<llvm::Module> parseAssemblyString(const std::string& s) {
        llvm::SMDiagnostic pa;
        std::unique_ptr<llvm::Module> mod(llvm::parseAssemblyString(s, pa, llvm::getGlobalContext()));
        if (!mod) {
            std::cout << pa.getMessage().str() << std::endl;
            abort();
        }
        return mod;
    }

    std::unique_ptr<llvm::Module> parseAssemblyString2(const std::string& s, llvm::SMDiagnostic& pa) {
        return llvm::parseAssemblyString(s, pa, llvm::getGlobalContext());
    }

    static uint64_t string_hash(const char *str) {
      uint64_t result(0);
      unsigned char c;
      while ((c = *(str++))) {
        result = result * 33 + uint8_t(c);
      }
      return result;
    }

    std::string IRToBitcode(const std::string& ir) {
        std::string bitcode;
        auto mod(parseAssemblyString(ir));
        writeBitcodeToFile(mod.get(), bitcode);
        return bitcode;
    }

    long getStructSize(const std::string& struct_type_str) {
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



    std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string& sInlineBitcode) {
        llvm::ErrorOr<std::unique_ptr<llvm::Module>> maybe(llvm::parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"),
                                          llvm::getGlobalContext()));
        if (maybe) {
            return std::move(maybe.get());
        } else {
            return nullptr;
        }
    }

    bool parseAssemblyInto(const std::string& asmcode, llvm::Module& M, llvm::SMDiagnostic& pa) {
        return llvm::parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), M, pa);
    }

    void writeBitcodeToFile(llvm::Module* M, std::string& bitcode) {
        llvm::raw_string_ostream bitstream(bitcode);
        llvm::WriteBitcodeToFile(M, bitstream);
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
        return modulePtr;
    }

    bool writeBitcodeToFile2(llvm::Module* M, const std::string& filename) {
        std::error_code errcode;
        llvm::raw_fd_ostream ss(filename, errcode, llvm::sys::fs::F_RW);
        if (errcode) {
            std::cout << errcode.message() << std::endl;
            return false;
        }
        llvm::WriteBitcodeToFile(M, ss);
        return true;
    }

    bool verifyModule(llvm::Module& M) {
        return llvm::verifyModule(M);
    }

    MutexGuard::MutexGuard()
        : _mg(new llvm::MutexGuard(ExecEngine->lock)) {}

    MutexGuard::~MutexGuard() {
        delete _mg;
    }

    std::string sanitizeType(llvm::Type *Type) {
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
    const std::regex globalSymRegex(
      "[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
      std::regex::optimize);

    // match "define @sym"
    const std::regex defineSymRegex(
      "define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
      std::regex::optimize | std::regex::ECMAScript);

    void insertMatchingSymbols(
        const std::string &code, const std::regex &regex,
        std::unordered_set<std::string> &containingSet) {
      std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
                std::sregex_token_iterator(),
                std::inserter(containingSet, containingSet.begin()));
    }

    std::unordered_set<std::string> globalSyms(const std::string& code)
    {
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
        const std::unordered_set<std::string> &sInlineSyms) {

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

    llvm::Module* jitCompile(const std::string& asmcode) {
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
        std::vector<std::string> res;

        auto func(GlobalMap::getFunction(fname.c_str()));
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
        auto func(GlobalMap::getFunction(name.c_str()));
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
        auto func(GlobalMap::getFunction(name.c_str()));
        if (!func) {
            return -1;
        }
        return func->getCallingConv();
    }

    const std::string getGlobalVariableType(const std::string& name) {
        std::string res;
        auto var(GlobalMap::getGlobalVariable(name.c_str()));
        if (!var) {
            return res;
        }

        llvm::raw_string_ostream ss(res);
        var->getType()->print(ss);
        return ss.str();
    }

    bool removeFunctionByName(const std::string& name) {
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
        auto var(EXTLLVM2::FindGlobalVariableNamed(name));
        if (!var) {
            return false;
        }
        var->dropAllReferences();
        var->removeFromParent();
        return true;
    }

    bool eraseFunctionByName(const std::string& name) {
        auto func(FindFunctionNamed(name));
        if (!func) {
            return false;
        }
        func->dropAllReferences();
        func->removeFromParent();
        //func->deleteBody();
        //func->eraseFromParent();
        return true;
    }

    // TODO fix up return type, callers can just cast
    //      for the moment
    void* findVoidFunctionByName(const std::string& name) {
        auto func(FindFunctionNamed(name));
        if (!func) {
            return 0;
        }
        return getPointerToFunction(func);
    }


    // TODO: reverse args when calling this!!
    //       but I'm pretty sure it will never have more than one arg
    // TODO: check no closures at call site!
    Result callCompiled(void *func_ptr, unsigned lgth, std::vector<EARG>& args) {
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
            res.tag = ArgType::VOID;
            break;
        default:
            return {ResultType::BAD, {}};
        }
        return {ResultType::GOOD, res};
    }

    void printAllModules() {
        for (auto module : getModules()) {
            std::string str;
            llvm::raw_string_ostream ss(str);
            ss << *module;
            printf("\n---------------------------------------------------\n%s", ss.str().c_str());
        }
    }

    void printLLVMFunction(const std::string& fname) {
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
        auto oldval(addGlobalMappingUnderEELock(sym.c_str(), reinterpret_cast<uintptr_t>(ptr)));
        return reinterpret_cast<void*>(oldval);
    }

    const std::string getNamedType(const std::string& name) {
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


} // namespace EXTLLVM2
} // namespace extemp
