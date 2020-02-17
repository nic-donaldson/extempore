// If EXTLLVM was so good why didn't they make an EXTLLVM2?
#include <EXTLLVM2.h>
#include <EXTMutex.h>
#include <EXTLLVMGlobalMap.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/ADT/STLExtras.h"

#include <vector>

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

    void initLLVM() {
        alloc_mutex.init();

        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        LLVMInitializeX86Disassembler();

        /*auto& context(llvm::getGlobalContext());
        auto module(llvm::make_unique<llvm::Module>("xtmmodule_0", context));
        M = module.get(); */
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

} // namespace EXTLLVM2
} // namespace extemp
