// If EXTLLVM was so good why didn't they make an EXTLLVM2?
#include <EXTLLVM2.h>
#include <EXTMutex.h>
#include <EXTLLVMGlobalMap.h>
#include <UNIV.h>

#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/ADT/STLExtras.h"

#include <vector>
#include <iostream>

namespace extemp {
namespace EXTLLVM2 {
    // should probably move this a bit closer
    // to where it is used
    EXTMutex alloc_mutex("alloc mutex");

    bool OPTIMIZE_COMPILES = true;
    llvm::ExecutionEngine* EE = nullptr;
    llvm::legacy::PassManager* PM = nullptr;
    llvm::legacy::PassManager* PM_NO = nullptr;
    llvm::Module* M = nullptr;
    std::vector<llvm::Module*> Ms;

    // TODO: make this static once it's fully moved over
    llvm::SectionMemoryManager* MM = nullptr;

    void initLLVM() {
        alloc_mutex.init();

        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        LLVMInitializeX86Disassembler();


        auto& context(llvm::getGlobalContext());
        auto module(llvm::make_unique<llvm::Module>("xtmmodule_0", context));
        M = module.get();
        addModule(M);
        if (!extemp::UNIV::ARCH.empty()) {
            M->setTargetTriple(extemp::UNIV::ARCH);
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
                    std::string att = feature.getValue()
                                      ? feature.getKey().str()
                                      : std::string("-") + feature.getKey().str();
                    lattrs.append(1, att);
                }
            }
            tm = factory.selectTarget(triple, "", cpu, lattrs);
        }
        extemp::EXTLLVM2::EE = factory.create(tm);

        extemp::EXTLLVM2::EE->DisableLazyCompilation(true);
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
        extemp::EXTLLVM2::initPassManagers();

        // tell LLVM about some built-in functions
        extemp::EXTLLVM2::EE->updateGlobalMapping("llvm_zone_destroy", uintptr_t(&llvm_zone_destroy));
        extemp::EXTLLVM2::EE->updateGlobalMapping("get_address_offset", (uint64_t)&get_address_offset);
        extemp::EXTLLVM2::EE->updateGlobalMapping("string_hash", (uint64_t)&string_hash);
        extemp::EXTLLVM2::EE->updateGlobalMapping("swap64i", (uint64_t)&swap64i);
        extemp::EXTLLVM2::EE->updateGlobalMapping("swap64f", (uint64_t)&swap64f);
        extemp::EXTLLVM2::EE->updateGlobalMapping("swap32i", (uint64_t)&swap32i);
        extemp::EXTLLVM2::EE->updateGlobalMapping("swap32f", (uint64_t)&swap32f);
        extemp::EXTLLVM2::EE->updateGlobalMapping("unswap64i", (uint64_t)&unswap64i);
        extemp::EXTLLVM2::EE->updateGlobalMapping("unswap64f", (uint64_t)&unswap64f);
        extemp::EXTLLVM2::EE->updateGlobalMapping("unswap32i", (uint64_t)&unswap32i);
        extemp::EXTLLVM2::EE->updateGlobalMapping("unswap32f", (uint64_t)&unswap32f);
        extemp::EXTLLVM2::EE->updateGlobalMapping("rsplit", (uint64_t)&rsplit);
        extemp::EXTLLVM2::EE->updateGlobalMapping("rmatch", (uint64_t)&rmatch);
        extemp::EXTLLVM2::EE->updateGlobalMapping("rreplace", (uint64_t)&rreplace);
        extemp::EXTLLVM2::EE->updateGlobalMapping("r64value", (uint64_t)&r64value);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_double", (uint64_t)&mk_double);
        extemp::EXTLLVM2::EE->updateGlobalMapping("r32value", (uint64_t)&r32value);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_float", (uint64_t)&mk_float);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_i64", (uint64_t)&mk_i64);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_i32", (uint64_t)&mk_i32);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_i16", (uint64_t)&mk_i16);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_i8", (uint64_t)&mk_i8);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_i1", (uint64_t)&mk_i1);
        extemp::EXTLLVM2::EE->updateGlobalMapping("string_value", (uint64_t)&string_value);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_string", (uint64_t)&mk_string);
        extemp::EXTLLVM2::EE->updateGlobalMapping("cptr_value", (uint64_t)&cptr_value);
        extemp::EXTLLVM2::EE->updateGlobalMapping("mk_cptr", (uint64_t)&mk_cptr);
        extemp::EXTLLVM2::EE->updateGlobalMapping("sys_sharedir", (uint64_t)&sys_sharedir);
        extemp::EXTLLVM2::EE->updateGlobalMapping("sys_slurp_file", (uint64_t)&sys_slurp_file);
        extemp::EXTLLVM2::EE->finalizeObject();
        return;
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

    void runPassManager(llvm::Module *m) {
        assert(PM);
        assert(PM_NO);

        if (OPTIMIZE_COMPILES) {
            PM->run(*m);
        } else {
            PM_NO->run(*m);
        }
    }

    void addModule(llvm::Module* Module) {
        for (const auto& function : Module -> getFunctionList()) {
            EXTLLVM::addFunction(function);
        }
        for (const auto& global : Module->getGlobalList()) {
            EXTLLVM::addGlobal(global);
        }
        Ms.push_back(Module);
    }

    uint64_t getSymbolAddress(const std::string& name) {
        return MM->getSymbolAddress(name);
    }

} // namespace EXTLLVM2
} // namespace extemp
