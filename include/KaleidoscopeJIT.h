//===- KaleidoscopeJIT.h - A simple JIT for Kaleidoscope --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Contains a simple JIT definition for use in the kaleidoscope tutorials.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_EXECUTIONENGINE_ORC_KALEIDOSCOPEJIT_H
#define LLVM_EXECUTIONENGINE_ORC_KALEIDOSCOPEJIT_H

#include "llvm/ADT/STLExtras.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/RTDyldMemoryManager.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/LambdaResolver.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Mangler.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <list>
#include <iostream>
#include <map>

#include <dlfcn.h>

namespace llvm {
namespace orc {

class KaleidoscopeJIT {
  private:
    std::unique_ptr<TargetMachine> TM;
    const DataLayout DL;
    RTDyldObjectLinkingLayer ObjectLayer;
    IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
    std::list<decltype(CompileLayer)::ModuleHandleT> Handles;
    std::map<std::string,uint64_t> GlobalMap;

  public:
    using ModuleHandle = decltype(CompileLayer)::ModuleHandleT;

    KaleidoscopeJIT()
            : TM(EngineBuilder().selectTarget()), DL(TM->createDataLayout()),
              ObjectLayer([]() { return std::make_shared<SectionMemoryManager>(); }),
              CompileLayer(ObjectLayer, SimpleCompiler(*TM)) {
        llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
    }

    void * openLibrary(const std::string& name) {
        dlerror();
        auto lib_ptr = dlopen(name.c_str(), RTLD_NOW);
        if (lib_ptr == nullptr) {
            std::cout << "Failed to open library with dlopen(): " << dlerror() << std::endl;
            return nullptr;
        }

        return lib_ptr;
    }

    bool bindSymbol(void * library_ptr, const std::string& sym) {
        auto ptr(dlsym(library_ptr, sym.c_str()));
        if (ptr) {
            GlobalMap.insert(std::pair<std::string,uint64_t>(sym, (uint64_t)ptr));
            return true;
        }
        return false;
    }

    TargetMachine &getTargetMachine() { return *TM; }

    ModuleHandle addModule(std::unique_ptr<Module> M) {
        // Build our symbol resolver:
        // Lambda 1: Look back into the JIT itself to find symbols that are part of
        //           the same "logical dylib".
        // Lambda 2: Search for external symbols in the host process.
        auto Resolver = createLambdaResolver(
            [&](const std::string &Name) {
                if (auto Sym = CompileLayer.findSymbol(Name, false))
                    return Sym;
                return JITSymbol(nullptr);
            },
            [](const std::string &Name) {
                if (auto SymAddr =
                    RTDyldMemoryManager::getSymbolAddressInProcess(Name))
                    return JITSymbol(SymAddr, JITSymbolFlags::Exported);
                return JITSymbol(nullptr);
            });

        // Add the set to the JIT with the resolver we created above and a newly
        // created SectionMemoryManager.
        auto handle = cantFail(CompileLayer.addModule(std::move(M),
                                                      std::move(Resolver)));
        Handles.push_back(handle);
        return handle;
    }

    JITSymbol findSymbol(const std::string Name) {
        std::string MangledName;
        raw_string_ostream MangledNameStream(MangledName);
        Mangler::getNameWithPrefix(MangledNameStream, Name, DL);

        for (auto it = Handles.rbegin(); it != Handles.rend(); ++it) {
            auto sym = CompileLayer.findSymbolIn(*it, MangledNameStream.str(), true);
            if (sym) {
                return sym;
            }
        }

        return CompileLayer.findSymbol(MangledNameStream.str(), true);
    }

    void removeModule(ModuleHandle H) {
        cantFail(CompileLayer.removeModule(H));
    }

    void *getPointerToFunction(Function *F) {
        auto sym = findSymbol(F->getName().str());
        if (sym) {
            auto expected_addr = sym.getAddress();
            if (expected_addr) {
                return (void*)expected_addr.get();
            }
        }
        return nullptr;
    }

    llvm::GenericValue runFunction(llvm::Function *F,
                                   llvm::ArrayRef<llvm::GenericValue> ArgValues) {
        auto func_type = F->getFunctionType();
        auto return_type = F->getReturnType();

        assert (func_type->getNumParams() == 0);
        assert (ArgValues.size() == 0);
        assert (return_type->getTypeID() == Type::VoidTyID);

        // No arguments, void function
        void (*f)() =  (void (*)())getPointerToFunction(F);

        f();

        llvm::GenericValue rv;
        rv.DoubleVal = 1.0;
        return rv;
    }
};

} // end namespace orc
} // end namespace llvm

#endif // LLVM_EXECUTIONENGINE_ORC_KALEIDOSCOPEJIT_H
