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

// must be included before anything which pulls in <Windows.h>
// just left this commented out here because this comment seem important
// #include "llvm/ADT/StringExtras.h"

#include "SchemeFFI.h"
#include "AudioDevice.h"
#include "UNIV.h"
#include "TaskScheduler.h"
#include "SchemeProcess.h"
#include "SchemeREPL.h"

#ifdef _WIN32
#include <Windows.h>
#include <Windowsx.h>
#include <filesystem>
#include <fstream>
#else
#include <dlfcn.h>
#include <dirent.h>
#endif

#include <fstream>
#include <unordered_map>

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

#include <EXTLLVM.h>
#include <SchemeLLVMFFI.h>

namespace extemp {
namespace SchemeFFI {

// I would like to move all of these into their own .cpp
#include "ffi/utility.inc"
#include "ffi/ipc.inc"
#include "ffi/assoc.inc"
#include "ffi/number.inc"
#include "ffi/sys.inc"
#include "ffi/sys_dsp.inc"
#include "ffi/sys_zone.inc"
#include "ffi/misc.inc"
#include "ffi/regex.inc"

// llvm_scheme foreign function -> string name
// also is not thread safe!
std::map<foreign_func, std::string> LLVM_SCHEME_FF_MAP;

// these two functions were originally declared with extern "C"
// but I can't see that it matters. am I missing something?
// if that detail isn't important they should be folded into
// the next two functions

const char* llvm_scheme_ff_get_name(foreign_func ff)
{
    return LLVM_SCHEME_FF_MAP[ff].c_str();
}

void llvm_scheme_ff_set_name(foreign_func ff,const char* name)
{
    LLVM_SCHEME_FF_MAP[ff] = std::string(name);
    return;
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

#define LLVM_DEFS \
        { "llvm:optimize", &extemp::SchemeFFI::LLVM::optimizeCompiles },    \
        { "llvm:jit-compile-ir-string", &extemp::SchemeFFI::LLVM::jitCompileIRString}, \
        { "llvm:get-function", &extemp::SchemeFFI::LLVM::get_function }, \
        { "llvm:get-globalvar", &extemp::SchemeFFI::LLVM::get_globalvar }, \
        { "llvm:get-struct-size", &extemp::SchemeFFI::LLVM::get_struct_size }, \
        { "llvm:get-named-struct-size", &extemp::SchemeFFI::LLVM::get_named_struct_size }, \
        { "llvm:get-function-args", &extemp::SchemeFFI::LLVM::get_function_args }, \
        { "llvm:get-function-varargs", &extemp::SchemeFFI::LLVM::get_function_varargs }, \
        { "llvm:get-function-type", &extemp::SchemeFFI::LLVM::get_function_type }, \
        { "llvm:get-function-calling-conv", &extemp::SchemeFFI::LLVM::get_function_calling_conv }, \
        { "llvm:get-global-variable-type", &extemp::SchemeFFI::LLVM::get_global_variable_type }, \
        { "llvm:get-function-pointer", &extemp::SchemeFFI::LLVM::get_function_pointer }, \
        { "llvm:remove-function", &extemp::SchemeFFI::LLVM::remove_function }, \
        { "llvm:remove-globalvar", &extemp::SchemeFFI::LLVM::remove_global_var }, \
        { "llvm:erase-function", &extemp::SchemeFFI::LLVM::erase_function }, \
        { "llvm:call-void-func", &extemp::SchemeFFI::LLVM::llvm_call_void_native }, \
        { "llvm:run", &extemp::SchemeFFI::LLVM::call_compiled },        \
        { "llvm:convert-float", &extemp::SchemeFFI::LLVM::llvm_convert_float_constant }, \
        { "llvm:convert-double", &extemp::SchemeFFI::LLVM::llvm_convert_double_constant }, \
        { "llvm:count", &extemp::SchemeFFI::LLVM::llvm_count },         \
        { "llvm:count-set", &extemp::SchemeFFI::LLVM::llvm_count_set }, \
        { "llvm:count++", &extemp::SchemeFFI::LLVM::llvm_count_inc },   \
        { "llvm:call-closure", &extemp::SchemeFFI::LLVM::callClosure }, \
        { "llvm:print", &extemp::SchemeFFI::LLVM::llvm_print_all_modules }, \
        { "llvm:print-function", &extemp::SchemeFFI::LLVM::printLLVMFunction }, \
        { "llvm:print-all-closures", &extemp::SchemeFFI::LLVM::llvm_print_all_closures }, \
        { "llvm:print-closure", &extemp::SchemeFFI::LLVM::llvm_print_closure }, \
        { "llvm:get-closure-work-name", &extemp::SchemeFFI::LLVM::llvm_closure_last_name }, \
        { "llvm:bind-symbol", &extemp::SchemeFFI::LLVM::bind_symbol },  \
        { "llvm:update-mapping", &extemp::SchemeFFI::LLVM::update_mapping }, \
        { "llvm:get-named-type", &extemp::SchemeFFI::LLVM::get_named_type }, \
        { "llvm:export-module", &extemp::SchemeFFI::LLVM::export_llvmmodule_bitcode }, \
        { "llvm:disassemble", &extemp::SchemeFFI::LLVM::llvm_disasm },  \
        { "llvm:ffi-set-name", &ff_set_name }, \
        { "llvm:ffi-get-name", &ff_get_name }, \
        { "llvm:add-llvm-alias", &add_llvm_alias }, \
        { "llvm:get-llvm-alias", &get_llvm_alias }
    
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

} // SchemeFFI
} // extemp

