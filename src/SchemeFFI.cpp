/*
 * Copyright (c) 2011, Andrew Sorensen
 *
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * Neither the name of the authors nor other contributors may be used to endorse
 * or promote products derived from this software without specific prior written
 * permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
///////////////////
// LLVM includes //
///////////////////

#include <fstream>

// must be included before anything which pulls in <Windows.h>
#include "llvm/ADT/StringExtras.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm-c/Core.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/Interpreter.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MutexGuard.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Verifier.h"

#include "SchemeFFI.h"
#include <SchemeLLVMFFI.h>
#include "AudioDevice.h"
#include "UNIV.h"
#include "TaskScheduler.h"
#include "SchemeProcess.h"
#include "SchemeREPL.h"
#include <unordered_set>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <Windowsx.h>
#include <experimental/filesystem>
#include <fstream>
#else
#include <dlfcn.h>
#include <dirent.h>
#endif

#ifdef DYLIB
#include <cmrc/cmrc.hpp>
CMRC_DECLARE(xtm);
#endif

// setting this define should make call_compiled thread safe BUT ...
// also extremely SLOW !

#define LLVM_EE_LOCK

#include <regex>

////////////////////////////////

#include "pcre.h"

#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <time.h>
#endif

#ifdef _WIN32
//#include <unistd.h>
#include <malloc.h>
#elif __APPLE__
#include <Cocoa/Cocoa.h>
#include <CoreFoundation/CoreFoundation.h>
#include <AppKit/AppKit.h>
#endif

#ifdef _WIN32
#define PRINT_ERROR(format, ...)                \
    ascii_error();                   \
    printf(format , __VA_ARGS__);                       \
    ascii_normal()
#else
#define PRINT_ERROR(format, args...)            \
    ascii_error();                   \
    printf(format , ## args);                   \
    ascii_normal()
#endif

#include <queue>
//#include <unistd.h>
#include <EXTMutex.h>
#include <EXTLLVM2.h>
#include <EXTLLVM.h>
namespace extemp { namespace SchemeFFI {
static llvm::Module* jitCompile(const std::string& String);
}}

namespace extemp {

namespace SchemeFFI {

#include "ffi/utility.inc"
#include "ffi/ipc.inc"
#include "ffi/assoc.inc"
#include "ffi/number.inc"
#include "ffi/sys.inc"
#include "ffi/sys_dsp.inc"
#include "ffi/sys_zone.inc"
#include "ffi/misc.inc"
#include "ffi/regex.inc"

    // llvm.inc
static pointer jitCompileIRString(scheme* Scheme, pointer Args)
{
    auto modulePtr(jitCompile(string_value(pair_car(Args))));
    if (!modulePtr) {
        return Scheme->F;
    }
    extemp::EXTLLVM::addModule(modulePtr);
    return mk_cptr(Scheme, modulePtr);
}

static pointer ff_set_name(scheme* Scheme, pointer Args)
{
   pointer x = pair_car(Args);
   foreign_func ff = x->_object._ff;
   char* name = string_value(pair_cadr(Args));
   llvm_scheme_ff_set_name(ff, name);
   return Scheme->T;
}

static pointer ff_get_name(scheme* Scheme, pointer Args)
{
   pointer x = pair_car(Args);
   foreign_func ff = x->_object._ff;
   const char* name = llvm_scheme_ff_get_name(ff);
   return mk_string(Scheme,name);
}

static pointer get_function(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::Function*>(func));
}

static pointer get_globalvar(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM::getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::GlobalVariable*>(var));
}

static pointer get_struct_size(scheme* Scheme, pointer Args)
{
    char* struct_type_str = string_value(pair_car(Args));
    unsigned long long hash = string_hash(struct_type_str);
    char name[128];
    sprintf(name,"_xtmT%lld",hash);
    char assm[1024];
    sprintf(assm,"%%%s = type %s",name,struct_type_str);

    llvm::SMDiagnostic pa;
    auto newM(llvm::parseAssemblyString(assm, pa, llvm::getGlobalContext()));
    if (!newM) {
        return Scheme->F;
    }
    auto type(newM->getTypeByName(name));
    if (!type) {
        return Scheme->F;
    }
    auto layout(new llvm::DataLayout(newM.get()));
    long size = layout->getStructLayout(type)->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme, size);
}

static llvm::StructType* getNamedType(const char* name) {
    return EXTLLVM::M->getTypeByName(name);
}

static pointer get_named_struct_size(scheme* Scheme, pointer Args)
{
    llvm::Module* M = EXTLLVM::M;
    auto type(getNamedType(string_value(pair_car(Args))));
    if (!type) {
        return Scheme->F;
    }
    auto layout(new llvm::DataLayout(M));
    long size = layout->getStructLayout(type)->getSizeInBytes();
    delete layout;
    return mk_integer(Scheme, size);
}

static char tmp_str_a[1024];
static char tmp_str_b[4096];

static pointer get_function_args(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
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
    pointer str = mk_string(Scheme, tmp_name);
    pointer p = cons(Scheme, str, Scheme->NIL);
    for (const auto& arg : func->getArgumentList()) {
        {
            EnvInjector injector(Scheme, p);
            std::string typestr2;
            llvm::raw_string_ostream ss2(typestr2);
            arg.getType()->print(ss2);
            tmp_name = ss2.str().c_str();
            if (arg.getType()->isStructTy()) {
                rsplit(eq_type_string, tmp_name, tmp_str_a, tmp_str_b);
                tmp_name = tmp_str_a;
            }
            str = mk_string(Scheme, tmp_name);
        }
        p = cons(Scheme, str, p);
    }
    return reverse_in_place(Scheme, Scheme->NIL, p);
}

static pointer get_function_varargs(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    return (func && func->isVarArg()) ? Scheme->T : Scheme->F;
}

static pointer get_function_type(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getFunctionType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}

static pointer get_function_calling_conv(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_integer(Scheme, func->getCallingConv());
}

static pointer get_global_variable_type(scheme* Scheme, pointer Args)
{
    using namespace llvm;
    auto var(extemp::EXTLLVM::getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    var->getType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}

static pointer get_function_pointer(scheme* Scheme, pointer Args)
{
    auto name(string_value(pair_car(Args)));
    void* p = EXTLLVM::EE->getPointerToGlobalIfAvailable(name);
    if (!p) { // look for it as a JIT-compiled function
        p = reinterpret_cast<void*>(EXTLLVM::EE->getFunctionAddress(name));
        if (!p) {
            return Scheme->F;
        }
    }
    return mk_cptr(Scheme, p);
}

static pointer remove_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM::EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    if (func->mayBeOverridden()) {
        func->dropAllReferences();
        func->removeFromParent();
        return Scheme->T;
    }
    printf("Cannot remove function with dependencies\n");
    return Scheme->F;
}

static pointer remove_global_var(scheme* Scheme, pointer Args)
{
    auto var(EXTLLVM::EE->FindGlobalVariableNamed(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    var->dropAllReferences();
    var->removeFromParent();
    return Scheme->T;
}

static pointer erase_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM::EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    func->dropAllReferences();
    func->removeFromParent();
    //func->deleteBody();
    //func->eraseFromParent();
    return Scheme->T;
}

static pointer llvm_call_void_native(scheme* Scheme, pointer Args)
{
    char name[1024];
    strcpy(name, string_value(pair_car(Args)));
    strcat(name, "_native");
    auto func(EXTLLVM::EE->FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    void* p = EXTLLVM::EE->getPointerToFunction(func);
    if (!p) {
        return Scheme->F;
    }
    ((void(*)(void)) p)();
    return Scheme->T;
}

static pointer call_compiled(scheme* Scheme, pointer Args)
{
    llvm::ExecutionEngine* EE = EXTLLVM::EE;
#ifdef LLVM_EE_LOCK
    llvm::MutexGuard locked(EE->lock);
#endif
    auto func(reinterpret_cast<llvm::Function*>(cptr_value(pair_car(Args))));
    if (unlikely(!func)) {
        printf("No such function\n");
        return Scheme->F;
    }
    func->getArgumentList();
    Args = pair_cdr(Args);
    unsigned lgth = list_length(Scheme, Args);
    if (unlikely(lgth != func->getArgumentList().size())) {
        printf("Wrong number of arguments for function!\n");
        return Scheme->F;
    }
    int i = 0;
    std::vector<llvm::GenericValue> fargs;
    fargs.reserve(lgth);
    for (const auto& arg : func->getArgumentList()) {
        pointer p = car(Args);
        Args = cdr(Args);
        if (is_integer(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::IntegerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            int width = arg.getType()->getPrimitiveSizeInBits();
            fargs[i].IntVal = llvm::APInt(width, ivalue(p));
        } else if (is_real(p)) {
            if (arg.getType()->getTypeID() == llvm::Type::FloatTyID) {
                fargs[i].FloatVal = rvalue(p);
            } else if (arg.getType()->getTypeID() == llvm::Type::DoubleTyID) {
                fargs[i].DoubleVal = rvalue(p);
            } else {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
        } else if (is_string(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            fargs[i].PointerVal = string_value(p);
        } else if (is_cptr(p)) {
            if (unlikely(arg.getType()->getTypeID() != llvm::Type::PointerTyID)) {
                printf("Bad argument type %i\n",i);
                return Scheme->F;
            }
            fargs[i].PointerVal = cptr_value(p);
        } else if (unlikely(is_closure(p))) {
            printf("Bad argument at index %i you can't pass in a scheme closure.\n",i);
            return Scheme->F;
        } else {
            printf("Bad argument at index %i\n",i);
            return Scheme->F;
        }
    }
    llvm::GenericValue gv = EE->runFunction(func, fargs);
    switch(func->getReturnType()->getTypeID()) {
    case llvm::Type::FloatTyID:
        return mk_real(Scheme, gv.FloatVal);
    case llvm::Type::DoubleTyID:
        return mk_real(Scheme, gv.DoubleVal);
    case llvm::Type::IntegerTyID:
        return mk_integer(Scheme, gv.IntVal.getZExtValue()); //  getRawData());
    case llvm::Type::PointerTyID:
        return mk_cptr(Scheme, gv.PointerVal);
    case llvm::Type::VoidTyID:
        return Scheme->T;
    default:
        return Scheme->F;
    }
}

static pointer llvm_convert_float_constant(scheme* Scheme, pointer Args)
{
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    llvm::APFloat apf(llvm::APFloat::IEEEsingle, llvm::StringRef(floatin));
    // TODO: if necessary, checks for inf/nan can be done here
    auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
    return mk_string(Scheme, (std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true)).c_str());
}

static pointer llvm_convert_double_constant(scheme* Scheme, pointer Args)
{
    static_assert(sizeof(double) == sizeof(uint64_t), "sizeof(double) must be 8 bytes");
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    llvm::APFloat apf(llvm::APFloat::IEEEdouble, llvm::StringRef(floatin));
    // TODO: if necessary, checks for inf/nan can be done here
    auto ival(llvm::APInt::doubleToBits(apf.convertToFloat()));
    return mk_string(Scheme, (std::string("0x") + llvm::utohexstr(ival.getLimitedValue(), true)).c_str());
}

static pointer llvm_count(scheme* Scheme, pointer Args)
{
    return mk_integer(Scheme, EXTLLVM::LLVM_COUNT);
}

static pointer llvm_count_set(scheme* Scheme, pointer Args)
{
    EXTLLVM::LLVM_COUNT = ivalue(pair_car(Args));
    return llvm_count(Scheme, Args);
}

static pointer llvm_count_inc(scheme* Scheme, pointer Args)
{
    ++EXTLLVM::LLVM_COUNT;
    return llvm_count(Scheme, Args);
}

static pointer callClosure(scheme* Scheme, pointer Args)
{
    uint32_t** closure = reinterpret_cast<uint32_t**>(cptr_value(pair_car(Args)));
    auto fptr(reinterpret_cast<int64_t (*)(void*, int64_t)>(closure[0]));
    return mk_integer(Scheme, (*fptr)(closure[0], ivalue(pair_cadr(Args))));
}

static pointer printLLVMModule(scheme* Scheme, pointer Args) // TODO: This isn't used?
{
    std::string str;
    llvm::raw_string_ostream ss(str);
    if (list_length(Scheme, Args) > 0) {
        const llvm::GlobalValue* val = extemp::EXTLLVM::getGlobalValue(string_value(pair_car(Args)));
        if (!val) {
            std::cerr << "No such value found in LLVM Module" << std::endl;
            return Scheme->F;
        }
        ss << *val;
        printf("At address: %p\n%s\n",val, ss.str().c_str());
    } else {
        ss << *extemp::EXTLLVM::M;
    }
    printf("%s", ss.str().c_str());
    return Scheme->T;
}

static pointer printLLVMFunction(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    std::string str;
    llvm::raw_string_ostream ss(str);
    ss << *func;
    puts(ss.str().c_str());
    return Scheme->T;
}

static pointer llvm_print_all_closures(scheme* Scheme, pointer Args) // TODO
{
    char* x = string_value(pair_car(Args));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "_.*");
    for (auto module : EXTLLVM::getModules()) {
        for (const auto& func : module->getFunctionList()) {
            if (func.hasName() && rmatch(rgx, func.getName().data())) {
                std::string str;
                llvm::raw_string_ostream ss(str);
                ss << func;
                printf("\n---------------------------------------------------\n%s", ss.str().c_str());
            }
        }
    }
    return Scheme->T;
}

static pointer llvm_print_all_modules(scheme* Scheme, pointer Args) // TODO
{
    for (auto module : EXTLLVM::getModules()) {
        std::string str;
        llvm::raw_string_ostream ss(str);
        ss << *module;
        printf("\n---------------------------------------------------\n%s", ss.str().c_str());
    }
    return Scheme->T;
}

static pointer llvm_print_closure(scheme* Scheme, pointer Args) // TODO
{
    auto fname(string_value(pair_car(Args)));
    for (auto module : EXTLLVM::getModules()) {
        for (const auto& func : module->getFunctionList()) {
            if (func.hasName() && !strcmp(func.getName().data(), fname)) {
                std::string str;
                llvm::raw_string_ostream ss(str);
                ss << func;
                if (ss.str().find_first_of("{") != std::string::npos) {
                    std::cout << str << std::endl;
                }
            }
        }
    }
    return Scheme->T;
}

static pointer llvm_closure_last_name(scheme* Scheme, pointer Args)
{
    auto x(string_value(pair_car(Args)));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "__[0-9]*");
    const char* last_name(nullptr);
    for (auto module : EXTLLVM::getModules()) {
        for (const auto& func : module->getFunctionList()) {
            if (func.hasName() && rmatch(rgx, func.getName().data())) {
                last_name = func.getName().data();
            }
        }
    }
    if (last_name) {
        return mk_string(Scheme, last_name);
    }
    return Scheme->F;
}

static pointer llvm_disasm(scheme* Scheme, pointer Args)
{
    int lgth = list_length(Scheme, Args);
    int syntax = (lgth > 1) ? ivalue(pair_cadr(Args)) : 1;
    if (syntax > 1) {
      std::cout << "Syntax argument must be either 0: at&t or 1: intel" << std::endl;
      std::cout << "The default is 1: intel" << std::endl;
      syntax = 1;
    }
    auto name(llvm_closure_last_name(Scheme, Args));
    auto fptr(reinterpret_cast<unsigned char*>(cptr_value(get_function_pointer(Scheme,
            cons(Scheme, name, pair_cdr(Args))))));
    return mk_string(Scheme, extemp::EXTLLVM::llvm_disassemble(fptr, syntax));
}

static pointer bind_symbol(scheme* Scheme, pointer Args)
{
    auto library(cptr_value(pair_car(Args)));
    auto sym(string_value(pair_cadr(Args)));

    llvm::ExecutionEngine* EE = EXTLLVM::EE;
    llvm::MutexGuard locked(EE->lock);
#ifdef _WIN32
    auto ptr(reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(library), sym)));
#else
    auto ptr(dlsym(library, sym));
#endif
    if (likely(ptr)) {
        EE->updateGlobalMapping(sym, reinterpret_cast<uint64_t>(ptr));
        return Scheme->T;
    }
    return Scheme->F;
}

static pointer update_mapping(scheme* Scheme, pointer Args)
{
    auto sym(string_value(pair_car(Args)));
    auto ptr(cptr_value(pair_cadr(Args)));
    llvm::ExecutionEngine* EE = EXTLLVM::EE;
    llvm::MutexGuard locked(EE->lock);
    // returns previous value of the mapping, or NULL if not set
    auto oldval(EE->updateGlobalMapping(sym, reinterpret_cast<uint64_t>(ptr)));
    return mk_cptr(Scheme, reinterpret_cast<void*>(oldval));
}

static std::unordered_map<std::string, std::string> LLVM_ALIAS_TABLE;

static pointer add_llvm_alias(scheme* Scheme, pointer Args)
{
    LLVM_ALIAS_TABLE[string_value(pair_car(Args))] = string_value(pair_cadr(Args));
    return Scheme->T;
}

static pointer get_llvm_alias(scheme* Scheme, pointer Args)
{
    auto iter(LLVM_ALIAS_TABLE.find(std::string(string_value(pair_car(Args)))));
    if (iter != LLVM_ALIAS_TABLE.end()) {
        return mk_string(Scheme, iter->second.c_str());
    }
    return Scheme->F;
}

static pointer get_named_type(scheme* Scheme, pointer Args)
{
    const char* name = string_value(pair_car(Args));
    if (name[0] == '%') {
        ++name;
    }
    int ptrDepth = 0;
    int len(strlen(name) - 1);
    while (len >= 0 && name[len--] == '*') {
        ++ptrDepth;
    }
    auto tt(getNamedType(std::string(name, len).c_str()));
    if (tt) {
        std::string typestr;
        llvm::raw_string_ostream ss(typestr);
        tt->print(ss);
        auto tmp_name = ss.str().c_str();
        if (tt->isStructTy()) {
            rsplit(" = type ", tmp_name, tmp_str_a, tmp_str_b);
            tmp_name = tmp_str_b;
        }
        return mk_string(Scheme, (std::string(tmp_str_b) + std::string(ptrDepth, '*')).c_str());
    }
    return Scheme->NIL;
}

static pointer get_global_module(scheme* Scheme, pointer Args)
{
    auto m(EXTLLVM::M);
    if (!m) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, m);
}

static pointer export_llvmmodule_bitcode(scheme* Scheme, pointer Args)
{
    auto m(reinterpret_cast<llvm::Module*>(cptr_value(pair_car(Args))));
    if (!m) {
        return Scheme->F;
    }
    auto filename(string_value(pair_cadr(Args)));
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
    fout << irStr; //ss.str();
    fout.close();
#else
    std::error_code errcode;
    llvm::raw_fd_ostream ss(filename, errcode, llvm::sys::fs::F_RW);
    if (errcode) {
      std::cout << errcode.message() << std::endl;
      return Scheme->F;
    }
    llvm::WriteBitcodeToFile(m,ss);
#endif
    return Scheme->T;
}

#define LLVM_DEFS \
        { "llvm:optimize", &extemp::SchemeFFI::LLVM::optimizeCompiles },    \
        { "llvm:jit-compile-ir-string", &jitCompileIRString}, \
        { "llvm:ffi-set-name", &ff_set_name }, \
        { "llvm:ffi-get-name", &ff_get_name }, \
        { "llvm:get-function", &get_function }, \
        { "llvm:get-globalvar", &get_globalvar }, \
        { "llvm:get-struct-size", &get_struct_size }, \
        { "llvm:get-named-struct-size", &get_named_struct_size }, \
        { "llvm:get-function-args", &get_function_args }, \
        { "llvm:get-function-varargs", &get_function_varargs }, \
        { "llvm:get-function-type", &get_function_type }, \
        { "llvm:get-function-calling-conv", &get_function_calling_conv }, \
        { "llvm:get-global-variable-type", &get_global_variable_type }, \
        { "llvm:get-function-pointer", &get_function_pointer }, \
        { "llvm:remove-function", &remove_function }, \
        { "llvm:remove-globalvar", &remove_global_var }, \
        { "llvm:erase-function", &erase_function }, \
        { "llvm:call-void-func", &llvm_call_void_native }, \
        { "llvm:run", &call_compiled }, \
        { "llvm:convert-float", &llvm_convert_float_constant }, \
        { "llvm:convert-double", &llvm_convert_double_constant }, \
        { "llvm:count", &llvm_count }, \
        { "llvm:count-set", &llvm_count_set }, \
        { "llvm:count++", &llvm_count_inc }, \
        { "llvm:call-closure", &callClosure }, \
        { "llvm:print", &llvm_print_all_modules }, \
        { "llvm:print-function", &printLLVMFunction }, \
        { "llvm:print-all-closures", &llvm_print_all_closures }, \
        { "llvm:print-closure", &llvm_print_closure }, \
        { "llvm:get-closure-work-name", &llvm_closure_last_name }, \
        { "llvm:disassemble", &llvm_disasm }, \
        { "llvm:bind-symbol", &bind_symbol }, \
        { "llvm:update-mapping", &update_mapping }, \
        { "llvm:add-llvm-alias", &add_llvm_alias }, \
        { "llvm:get-llvm-alias", &get_llvm_alias }, \
        { "llvm:get-named-type", &get_named_type }, \
        { "llvm:get-global-module", &get_global_module }, \
        { "llvm:export-module", &export_llvmmodule_bitcode }

    // /llvm.inc

#include "ffi/clock.inc"

void initSchemeFFI(scheme* sc)
{
    static struct {
        const char* name;
        uint32_t    value;
    } integerTable[] = {
        { "*au:block-size*", UNIV::NUM_FRAMES },
        { "*au:samplerate*", UNIV::SAMPLE_RATE },
        { "*au:channels*", UNIV::CHANNELS },
        { "*au:in-channels*", UNIV::IN_CHANNELS },
    };
    for (auto& elem: integerTable) {
        scheme_define(sc, sc->global_env, mk_symbol(sc, elem.name), mk_integer(sc, elem.value));
    }
    static struct {
        const char*  name;
        foreign_func func;
    } funcTable[] = {
        UTILITY_DEFS,
        IPC_DEFS,
        ASSOC_DEFS,
        NUMBER_DEFS,
        SYS_DEFS,
        SYS_DSP_DEFS,
        SYS_ZONE_DEFS,
        MISC_DEFS,
        REGEX_DEFS,
        LLVM_DEFS,
        CLOCK_DEFS
    };
    for (auto& elem : funcTable) {
        scheme_define(sc, sc->global_env, mk_symbol(sc, elem.name), mk_foreign_func(sc, elem.func));
    }
}

static std::string fileToString(const std::string &fileName) {
    std::ifstream inStream(fileName);
    std::stringstream inString;
    inString << inStream.rdbuf();
    return inString.str();
}

static const std::string inlineDotLLString() {
#ifdef DYLIB
    auto fs = cmrc::xtm::get_filesystem();
    auto data = fs.open("runtime/inline.ll");
    static const std::string sInlineDotLLString(data.begin(), data.end());
#else
    static const std::string sInlineDotLLString(
      fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll"));
#endif

    return sInlineDotLLString;
}

static const std::string bitcodeDotLLString() {
#ifdef DYLIB
    auto fs = cmrc::xtm::get_filesystem();
    auto data = fs.open("runtime/bitcode.ll");
    static const std::string sBitcodeDotLLString(data.begin(), data.end());
#else
    static const std::string sBitcodeDotLLString(
      fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll"));
#endif

    return sBitcodeDotLLString;
}

static std::string IRToBitcode(const std::string &ir) {
    std::string bitcode;
    llvm::SMDiagnostic pa;
    auto mod(llvm::parseAssemblyString(ir, pa, llvm::getGlobalContext()));
    if (!mod) {
        pa.print("IRToBitcode", llvm::outs());
        std::abort();
    }
    llvm::raw_string_ostream bitstream(bitcode);
    llvm::WriteBitcodeToFile(mod.get(), bitstream);
    return bitcode;
}

static std::unique_ptr<llvm::Module> parseBitcodeFile(const std::string &sInlineBitcode) {
    llvm::ErrorOr<std::unique_ptr<llvm::Module>> maybe(llvm::parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), llvm::getGlobalContext()));

    if (maybe) {
        return std::move(maybe.get());
    } else {
        return nullptr;
    }
}

// match @symbols @like @this_123
static const std::regex sGlobalSymRegex(
  "[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
  std::regex::optimize);

// match "define @sym"
static const std::regex sDefineSymRegex(
  "define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)",
  std::regex::optimize | std::regex::ECMAScript);

// template is temporary, we'll remove this once the refactoring is done
template <class T>
static void insertMatchingSymbols(
  const std::string &code, const std::regex &regex,
  // std::unordered_set<std::string> &containingSet
  T &containingSet)
{
    std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
              std::sregex_token_iterator(),
              std::inserter(containingSet, containingSet.begin()));
}

static std::string SanitizeType(llvm::Type* Type)
{
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

static std::string globalDeclaration(const llvm::Function *func, const std::string& sym) {
    std::stringstream ss;
    ss << "declare "
       << SanitizeType(func->getReturnType())
       << " @" << sym << " (";

    bool first(true);
    for (const auto &arg : func->getArgumentList()) {
        if (!first) {
            ss << ", ";
        } else {
            first = false;
        }
        ss << SanitizeType(arg.getType());
    }
    if (func->isVarArg()) {
        ss << ", ...";
    }
    ss << ")\n";
    return ss.str();
}

static std::string globalDeclarations(const std::string &asmcode, const std::unordered_set<std::string>& sInlineSyms) {
    std::vector<std::string> symbols;

    // Copy all @symbols @like @this into symbols
    insertMatchingSymbols(asmcode, sGlobalSymRegex, symbols);

    std::sort(symbols.begin(), symbols.end());
    auto end(std::unique(symbols.begin(), symbols.end()));

    std::unordered_set<std::string> ignoreSyms;
    insertMatchingSymbols(asmcode, sDefineSymRegex, ignoreSyms);

    std::string declarations;
    llvm::raw_string_ostream dstream(declarations);

    // Iterating over all @symbols @in @asmcode matching sGlobalSymRegex
    for (auto iter = symbols.begin(); iter != end; ++iter) {

        const char* sym(iter->c_str());
        if (sInlineSyms.find(sym) != sInlineSyms.end() || ignoreSyms.find(sym) != ignoreSyms.end()) {
            continue;
        }
        auto gv = extemp::EXTLLVM::getGlobalValue(sym);
        if (!gv) {
            continue;
        }
        const llvm::Function* func(llvm::dyn_cast<llvm::Function>(gv));
        if (func) {
            dstream << globalDeclaration(func, sym);
        } else {
            auto str(SanitizeType(gv->getType()));
            dstream << '@' << sym << " = external global "
                    << str.substr(0, str.length() - 1) << '\n';
        }
    }
    return dstream.str();
}

static llvm::Module* jitCompile(const std::string& String)
{
    // Create some module to put our function into it.
    using namespace llvm;
    legacy::PassManager* PM = extemp::EXTLLVM::PM;
    legacy::PassManager* PM_NO = extemp::EXTLLVM::PM_NO;

    std::string asmcode(String);
    SMDiagnostic pa;

    static std::string sInlineString; // This is a hack for now, but it *WORKS*
    static std::string sInlineBitcode;
    static std::unordered_set<std::string> sInlineSyms;

    if (sInlineString.empty()) {
        sInlineString = bitcodeDotLLString();
        insertMatchingSymbols(sInlineString, sGlobalSymRegex, sInlineSyms);

        std::string tString = inlineDotLLString();
        insertMatchingSymbols(tString, sGlobalSymRegex, sInlineSyms);
    }

    if (sInlineBitcode.empty()) {
        // need to avoid parsing the types twice
        static bool first(true);
        if (!first) {
            sInlineBitcode = IRToBitcode(sInlineString);
            sInlineString = inlineDotLLString();
        } else {
            first = false;
        }
    }

    std::unique_ptr<llvm::Module> newModule;

    const std::string declarations = globalDeclarations(asmcode, sInlineSyms);

    if (!sInlineBitcode.empty()) {
        auto modOrErr(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));
        if (likely(modOrErr)) {
            newModule = std::move(modOrErr.get());
            asmcode = sInlineString + declarations + asmcode;
            if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {
                std::cout << "**** DECL ****\n"
                          << declarations
                          << "**** ENDDECL ****\n"
                          << std::endl;
                newModule.reset();
            }
        }
    } else {
       newModule = parseAssemblyString(asmcode, pa, getGlobalContext());
    }
    if (newModule) {
        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }
        if (EXTLLVM2::OPTIMIZE_COMPILES) {
            PM->run(*newModule);
        } else {
            PM_NO->run(*newModule);
        }
    }
    //std::stringstream ss;
    if (unlikely(!newModule))
    {
// std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" << std::endl;
// std::cout << pa.getMessage().str() << std::endl << pa.getLineNo() << std::endl;
        std::string errstr;
        llvm::raw_string_ostream ss(errstr);
        pa.print("LLVM IR",ss);
        printf("%s\n",ss.str().c_str());
        return nullptr;
    } else if (extemp::EXTLLVM::VERIFY_COMPILES && verifyModule(*newModule)) {
        std::cout << "\nInvalid LLVM IR\n";
        return nullptr;
    }

    llvm::Module *modulePtr = newModule.get();
    extemp::EXTLLVM::EE->addModule(std::move(newModule));
    extemp::EXTLLVM::EE->finalizeObject();
    return modulePtr;
}

}

} // end namespace

