// If EXTLLVM was so good why didn't they make an EXTLLVM2?
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Support/MutexGuard.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/ADT/STLExtras.h"

// if you remove this it segfaults for some reason?
// if you look at the header it does some kind of magic so
// maybe that's not unexpected
#include "llvm/ExecutionEngine/MCJIT.h"

#include <EXTLLVM2.h>
#include <EXTMutex.h>
#include <EXTLLVMGlobalMap.h>
#include <UNIV.h>

#include <vector>
#include <iostream>

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
        extemp::EXTLLVM2::ExecEngine = factory.create(tm);

        extemp::EXTLLVM2::ExecEngine->DisableLazyCompilation(true);
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
            EXTLLVM::GlobalMap::addFunction(function);
        }
        for (const auto& global : Module->getGlobalList()) {
            EXTLLVM::GlobalMap::addGlobal(global);
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

    llvm::StructType* getTypeByName(const char* name) {
        return FirstModule->getTypeByName(name);
    }

    long getNamedStructSize(llvm::StructType* type) {
        auto layout(new llvm::DataLayout(FirstModule));
        long size = layout->getStructLayout(type)->getSizeInBytes();
        delete layout;
        return size;
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
        llvm::TargetMachine *TM = extemp::EXTLLVM2::getTargetMachine();
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

} // namespace EXTLLVM2
} // namespace extemp
