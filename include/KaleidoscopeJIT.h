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

// TODO delete
#include <iostream>

namespace llvm {
namespace orc {

class KaleidoscopeJIT {
private:
  std::unique_ptr<TargetMachine> TM;
  const DataLayout DL;
  RTDyldObjectLinkingLayer ObjectLayer;
  IRCompileLayer<decltype(ObjectLayer), SimpleCompiler> CompileLayer;
  std::list<decltype(CompileLayer)::ModuleHandleT> ModuleHandles;
  std::list<decltype(ObjectLayer)::ObjHandleT> ObjHandles;

public:
  using ModuleHandle = decltype(CompileLayer)::ModuleHandleT;
  using ObjHandle = decltype(ObjectLayer)::ObjHandleT;

  KaleidoscopeJIT()
      : TM(EngineBuilder().selectTarget()), DL(TM->createDataLayout()),
        ObjectLayer([]() { return std::make_shared<SectionMemoryManager>(); }),
        CompileLayer(ObjectLayer, SimpleCompiler(*TM)) {
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
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
    ModuleHandles.push_back(handle);
    return handle;
  }

  JITSymbol findSymbol(const std::string Name) {
    std::string MangledName;
    raw_string_ostream MangledNameStream(MangledName);
    Mangler::getNameWithPrefix(MangledNameStream, Name, DL);

    for (auto it = ModuleHandles.rbegin(), e = ModuleHandles.rend(); it != e; ++it) {
        auto sym = CompileLayer.findSymbolIn(*it, MangledNameStream.str(), true);
        if (sym) {
            return sym;
        }
    }
    
    for (auto it = ObjHandles.rbegin(), e = ObjHandles.rend(); it != e; ++it) {
        auto sym = ObjectLayer.findSymbolIn(*it, MangledNameStream.str(), true);
        if (sym) {
            return sym;
        }
    }

    return JITSymbol(nullptr);
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
  
  bool loadLibrary(const std::string& path) {
      using namespace llvm::object;
      llvm::Expected<OwningBinary<ObjectFile>> maybe_obj_file = ObjectFile::createObjectFile(path.c_str());
      
      if (!maybe_obj_file) {
          return false;
      }
      
      std::shared_ptr<OwningBinary<ObjectFile>> obj_file(new OwningBinary<ObjectFile>(std::move(maybe_obj_file.get())));
      llvm::Expected<ObjHandle> handle = ObjectLayer.addObject(obj_file, nullptr); // no resolver, doesn't seem to be used?
      
      if (!handle) {
          return false;
      }
      
      ObjHandles.push_back(*handle);
      
      return true;
  }
  
  void delete_me() {
      llvm::Expected<llvm::object::OwningBinary<llvm::object::ObjectFile> > maybe_obj_file = llvm::object::ObjectFile::createObjectFile("/home/nic/code/extempore/extempore/libs/aot-cache/xtmbase.so");        
      
      if (maybe_obj_file) {
          std::shared_ptr<llvm::object::OwningBinary<llvm::object::ObjectFile>> obj_file(new llvm::object::OwningBinary<llvm::object::ObjectFile> (std::move(maybe_obj_file.get())));
                    
          llvm::Expected<ObjHandle> handle = ObjectLayer.addObject(obj_file,
                                              nullptr);
          
          if (handle) {
              auto sym = ObjectLayer.findSymbolIn(handle.get(), "audio_64bit_adhoc_W2kxXQ_setter", false);
              if (sym) {
                  std::cout << "yes" << std::endl;
                  auto addr = sym.getAddress();
                  if (addr) {
                      std::cout << "double yes" << std::endl;
                      std::cout << std::hex << addr.get() << std::endl;
                  } else {
                      std::cout << "yes no" << std::endl;
                  }
              } else {
                  std::cout << "oh no" << std::endl;
              }
          }                    
          
      }
  }
};

} // end namespace orc
} // end namespace llvm

#endif // LLVM_EXECUTIONENGINE_ORC_KALEIDOSCOPEJIT_H
