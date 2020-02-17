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
#include <EXTLLVM2.h>
#include <EXTLLVMGlobalMap.h>
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
#include <filesystem>
#include <fstream>
#else
#include <dlfcn.h>
#include <dirent.h>
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

#include <EXTMutex.h>
#include <EXTLLVM.h>
#include <LLVMIRCompilation.h>

namespace extemp {

namespace SchemeFFI {

static llvm::Module* jitCompile(const std::string asmcode);
static LLVMIRCompilation IRCompiler;

#include "ffi/utility.inc"
#include "ffi/ipc.inc"
#include "ffi/assoc.inc"
#include "ffi/number.inc"
#include "ffi/sys.inc"
#include "ffi/sys_dsp.inc"
#include "ffi/sys_zone.inc"
#include "ffi/misc.inc"
#include "ffi/regex.inc"

// include "ffi/llvm.inc"
static pointer optimizeCompiles(scheme* Scheme, pointer Args)
{
    EXTLLVM2::setOptimize((pair_car(Args) == Scheme->T));
    return Scheme->T;
}

static pointer jitCompileIRString(scheme* Scheme, pointer Args)
{
    auto modulePtr(jitCompile(string_value(pair_car(Args))));
    if (!modulePtr) {
        return Scheme->F;
    }
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

// TODO: do we still need this function?
static llvm::StructType* getNamedType(const char* name) {
    return EXTLLVM2::getTypeByName(name);
}

static pointer get_named_struct_size(scheme* Scheme, pointer Args)
{
    auto type(getNamedType(string_value(pair_car(Args))));
    if (!type) {
        return Scheme->F;
    }
    return mk_integer(Scheme, EXTLLVM2::getNamedStructSize(type));
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
    void* p = EXTLLVM2::getPointerToGlobalIfAvailable(name);
    if (!p) { // look for it as a JIT-compiled function
        p = reinterpret_cast<void*>(EXTLLVM2::getFunctionAddress(name));
        if (!p) {
            return Scheme->F;
        }
    }
    return mk_cptr(Scheme, p);
}

static pointer remove_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM2::FindFunctionNamed(string_value(pair_car(Args))));
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
    auto var(EXTLLVM2::FindGlobalVariableNamed(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    var->dropAllReferences();
    var->removeFromParent();
    return Scheme->T;
}

static pointer erase_function(scheme* Scheme, pointer Args)
{
    auto func(EXTLLVM2::FindFunctionNamed(string_value(pair_car(Args))));
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
    auto func(EXTLLVM2::FindFunctionNamed(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    void* p = EXTLLVM2::getPointerToFunction(func);
    if (!p) {
        return Scheme->F;
    }
    ((void(*)(void)) p)();
    return Scheme->T;
}

static pointer call_compiled(scheme* Scheme, pointer Args)
{
#ifdef LLVM_EE_LOCK
    llvm::MutexGuard locked(EXTLLVM2::ExecEngine->lock);
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
    llvm::GenericValue gv = EXTLLVM2::ExecEngine->runFunction(func, fargs);
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
    for (auto module : EXTLLVM2::getModules()) {
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
    for (auto module : EXTLLVM2::getModules()) {
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
    for (auto module : EXTLLVM2::getModules()) {
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
    for (auto module : EXTLLVM2::getModules()) {
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

    llvm::ExecutionEngine* EE = EXTLLVM2::ExecEngine;
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

    auto oldval(EXTLLVM2::addGlobalMappingUnderEELock(sym, reinterpret_cast<uintptr_t>(ptr)));
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
        { "llvm:optimize", &optimizeCompiles }, \
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
        { "llvm:export-module", &export_llvmmodule_bitcode }
    
    
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



static std::string fileToString(const std::string& fileName)
{
    std::ifstream inStream(fileName);
    std::stringstream inString;
    inString << inStream.rdbuf();
    return inString.str();
}

// insertMatchingSymbols finds tokens in code that match regex and inserts them into containingSet
static void insertMatchingSymbols(const std::string& code, const std::regex& regex, std::unordered_set<std::string>& containingSet)
{
    return LLVMIRCompilation::insertMatchingSymbols(code, regex, containingSet);
    std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
              std::sregex_token_iterator(), std::inserter(containingSet, containingSet.begin()));
}

static void loadInitialBitcodeAndSymbols(std::string& sInlineDotLLString, std::unordered_set<std::string>& sInlineSyms, std::string& sInlineBitcode)
{
    using namespace llvm;
    SMDiagnostic pa;

    sInlineDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll");
    const std::string bitcodeDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll");
    insertMatchingSymbols(bitcodeDotLLString, extemp::LLVMIRCompilation::globalSymRegex, sInlineSyms);
    insertMatchingSymbols(sInlineDotLLString, extemp::LLVMIRCompilation::globalSymRegex, sInlineSyms);

    // put bitcode.ll -> sInlineBitcode
    auto newModule(
        parseAssemblyString(bitcodeDotLLString, pa, getGlobalContext()));

    if (!newModule) {
      std::cout << pa.getMessage().str() << std::endl;
      abort();
    }

    llvm::raw_string_ostream bitstream(sInlineBitcode);
    llvm::WriteBitcodeToFile(newModule.get(), bitstream);
}

static llvm::Module* jitCompile(std::string asmcode)
{
    // so the first file that comes through is runtime/init.ll
    // it begins with
    // %mzone = type { i8*, i64, i64, i64, i8*, %mzone* rbrace if I actually type the brace emacs decides to reindent everything i love computers
    // std::cout << asmcode << std::endl;
    // std::cout << "----------------------------------------------------------" << std::endl;

    using namespace llvm;

    // the first time we call jitCompile it's init.ll which requires
    // special behaviour
    static bool isThisInitDotLL(true);

    static bool sLoadedInitialBitcodeAndSymbols(false);
    static std::string sInlineDotLLString;
    static std::string sInlineBitcode; // contains compiled bitcode from bitcode.ll
    static std::unordered_set<std::string> sInlineSyms;

    if (sLoadedInitialBitcodeAndSymbols == false) {
        loadInitialBitcodeAndSymbols(sInlineDotLLString, sInlineSyms, sInlineBitcode);
        sLoadedInitialBitcodeAndSymbols = true;
    }

    // contents of sInlineSyms:
    /*
is_integer, llvm_zone_mark_size, llvm_zone_mark, llvm_zone_create, llvm_zone_create_extern, llvm_peek_zone_stack, llvm_peek_zone_stack_extern, ascii_text_color, llvm_now, is_cptr_or_str, is_cptr, is_real, is_type, sscanf, fscanf, ftoui64, ftoi16, dtoi1, i32toui64, ftod, is_integer_extern, i16toi1, i64toi32, i16toi8, sprintf, ftoi8, i64toi16, i32toptr, dtoui8, i16toi32, i8toui64, fprintf, ftoi1, i1toi16, ftoui32, llvm_zone_ptr_set_size, is_string, ftoi64, printf, i8toi1, i64tod, i32toi1, impc_null, impc_false, i64toi8, ui64tof, impc_true, dtoi32, i8toi64, ptrtoi32, i1toi8, i64toi1, ftoi32, i16toui64, ui8tod, i32toi64, i1toi64, dtof, i8toi16, ftoui16, llvm_push_zone_stack, i32toi8, i32toi16, ftoui1, ui1tod, i64tof, ptrtoi64, new_address_table, i8toui32, i32tof, i8tof, i1tof, ui32tof, ui16tof, ui8tof, ui1tof, dtoui32, dtoi64, i16tod, dtoi16, i1toi32, dtoi8, ascii_text_color_extern, i16toui32, dtoui64, i1tod, fp80ptrtod, dtoui16, dtoui1, i32tod, ftoui8, i8toi32, i8tod, llvm_zone_reset, TIME, i16toi64, ui64tod, i16tof, ui32tod, ui16tod, i64toptr, llvm_push_zone_stack_extern, ptrtoi16, i16toptr


    for (const auto &sym : sInlineSyms) {
        std::cout << sym << ", ";
    }
    std::cout << "-------------------------------------------------------------------" << std::endl;

e.g. new_address_table is the first definition in inline.ll it appears as @new_address_table
which matches the globalsymregex we're using
from llvm 3.8.0 docs:
"LLVM identifiers come in two basic types: global and local. Global identifiers (functions, global variables) begin with the '@' character."

so basically all the global syms, "@thing", appear in sInlineSyms

this is pretty rudimentary won't handle LLVM comments or linkage types e.g. "private".
should replace this with Module introspection/reflection

"LLVM programs are composed of Module‘s, each of which is a translation unit of the input programs. Each module consists of functions, global variables, and symbol table entries. Modules may be combined together with the LLVM linker, which merges function (and global variable) definitions, resolves forward declarations, and merges symbol table entries."
    */

    const std::string declarations = IRCompiler.necessaryGlobalDeclarations(asmcode, sInlineSyms);

    // std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;

    std::unique_ptr<llvm::Module> newModule = nullptr;
    SMDiagnostic pa;

    if (!isThisInitDotLL) {
        // module from bitcode.ll
        auto module(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));

        if (likely(module)) {
            newModule = std::move(module.get());
            // so every module but init.ll gets prepended with bitcode.ll, inline.ll, and any global declarations?
            asmcode = sInlineDotLLString + declarations + asmcode;
            if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {
                std::cout << "**** DECL ****\n" << declarations << "**** ENDDECL ****\n" << std::endl;
                newModule.reset();
            }
        }
    }

    if (isThisInitDotLL) {
        newModule = parseAssemblyString(asmcode, pa, getGlobalContext());
    }

    if (unlikely(!newModule)) {
        // std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" << std::endl;
        // std::cout << pa.getMessage().str() << std::endl << pa.getLineNo() << std::endl;

        std::string errstr;
        llvm::raw_string_ostream ss(errstr);
        pa.print("LLVM IR", ss);
        printf("%s\n", ss.str().c_str());
        return nullptr;
    }

    if (extemp::EXTLLVM::VERIFY_COMPILES && verifyModule(*newModule)) { // i can't believe this function returns true on an error
        std::cout << "\nInvalid LLVM IR\n";
        return nullptr;
    }

    if (unlikely(!extemp::UNIV::ARCH.empty())) {
        newModule->setTargetTriple(extemp::UNIV::ARCH);
    }

    // Probably shouldn't be unwrapping a unique_ptr here
    // but we can think about that another time
    llvm::Module* modulePtr = extemp::EXTLLVM2::addModule(std::move(newModule));

    isThisInitDotLL = false;

    return modulePtr;
}
} // SchemeFFI
} // extemp

