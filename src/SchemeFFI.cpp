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

#include <queue>
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
#include "ffi/llvm.inc"
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

static std::regex sGlobalSymRegex = LLVMIRCompilation::sGlobalSymRegex;
static std::regex sDefineSymRegex = LLVMIRCompilation::sDefineSymRegex;

static std::string fileToString(const std::string& fileName)
{
    std::ifstream inStream(fileName);
    std::stringstream inString;
    inString << inStream.rdbuf();
    return inString.str();
}

static void insertMatchingSymbols(const std::string& code, const std::regex& regex, std::unordered_set<std::string>& containingSet)
{
    std::copy(std::sregex_token_iterator(code.begin(), code.end(), regex, 1),
              std::sregex_token_iterator(), std::inserter(containingSet, containingSet.begin()));
}

static llvm::Module* jitCompile(std::string asmcode)
{
    // so the first file that comes through is runtime/init.ll
    // it begins with
    // %mzone = type { i8*, i64, i64, i64, i8*, %mzone* rbrace
    // std::cout << asmcode << std::endl;
    // std::cout << "----------------------------------------------------------" << std::endl;

    using namespace llvm;

    // Create an LLVM module to put our function into
    // this comment feels like it needs to be moved

    SMDiagnostic pa;

    static bool sLoadedInitialBitcodeAndSymbols(false);
    static std::string sInlineDotLLString;
    static std::string sBitcodeDotLLString;

    static std::string sInlineBitcode; // contains compiled bitcode from bitcode.ll

    static std::unordered_set<std::string> sInlineSyms;

    if (sLoadedInitialBitcodeAndSymbols == false) {
        sInlineDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll");
        sBitcodeDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll");

        insertMatchingSymbols(sBitcodeDotLLString, sGlobalSymRegex, sInlineSyms);
        insertMatchingSymbols(sInlineDotLLString, sGlobalSymRegex, sInlineSyms);

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
    */

    static unsigned long jitCount(0);
    static bool haveBitcode(false);
    // on the first run this will be true
    // on the second run too I think
    if (jitCount == 1) {
        // trying to understand why this can't be run earlier!
        // if we run it on the first time through then it will be prepended to whatever is coming through,
        // which is init.ll

        // need to avoid parsing the types twice

        auto newModule(
            parseAssemblyString(sBitcodeDotLLString, pa, getGlobalContext()));

        if (!newModule) {
            std::cout << pa.getMessage().str() << std::endl;
            abort();
        }

        llvm::raw_string_ostream bitstream(sInlineBitcode);
        llvm::WriteBitcodeToFile(newModule.get(), bitstream);
        haveBitcode = true;
    }
    jitCount += 1;

    std::unordered_set<std::string> symbols;
    insertMatchingSymbols(asmcode, sGlobalSymRegex, symbols);

    std::unordered_set<std::string> ignoreSyms;
    insertMatchingSymbols(asmcode, sDefineSymRegex, ignoreSyms);

    std::string declarations;
    std::stringstream dstream(declarations);
    for (auto iter = symbols.begin(); iter != symbols.end(); ++iter) {
        const char* sym(iter->c_str());

        // if the symbol from asmcode is present in inline.ll/bitcode.ll
        // no need to declare it again?
        if (sInlineSyms.find(sym) != sInlineSyms.end()) {
            continue;
        }

        // if the symbol is declared in asmcode no need to declare it again
        if (ignoreSyms.find(sym) != ignoreSyms.end()) {
            continue;
        }

        auto gv = extemp::EXTLLVM::getGlobalValue(sym);
        if (!gv) {
            continue;
        }

        auto func(llvm::dyn_cast<llvm::Function>(gv));
        if (func) {
            dstream << "declare " << LLVMIRCompilation::SanitizeType(func->getReturnType()) << " @" << sym << " (";

            bool first(true);
            for (const auto& arg : func->getArgumentList()) {
                if (!first) {
                    dstream << ", ";
                } else {
                    first = false;
                }
                dstream << LLVMIRCompilation::SanitizeType(arg.getType());
            }

            if (func->isVarArg()) {
                dstream << ", ...";
            }
            dstream << ")\n";
        } else {
            auto str(LLVMIRCompilation::SanitizeType(gv->getType()));
            dstream << '@' << sym << " = external global " << str.substr(0, str.length() - 1) << '\n';
        }
    }

    // std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;

    std::unique_ptr<llvm::Module> newModule = nullptr;

    // once we have the inlinebitcode
    if (haveBitcode) {
        // module from bitcode.ll
        auto module(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));

        if (likely(module)) {
            newModule = std::move(module.get());
            asmcode = sInlineDotLLString + dstream.str() + asmcode;
            if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {
                std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;
                newModule.reset();
            }
        }
    }

    if (jitCount == 1) {
        // If we don't have the bitcode
        // when is this true?
        // on our very first run through!
        // init.ll is the code on the first run
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
    } else if (extemp::EXTLLVM::VERIFY_COMPILES && verifyModule(*newModule)) { // i can't believe this function returns true on an error
        std::cout << "\nInvalid LLVM IR\n";
        return nullptr;
    }

    if (unlikely(!extemp::UNIV::ARCH.empty())) {
        newModule->setTargetTriple(extemp::UNIV::ARCH);
    }

    // Probably shouldn't be unwrapping a unique_ptr here
    // but we can think about that another time
    llvm::Module *modulePtr = newModule.get();
    EXTLLVM::runPassManager(modulePtr);
    extemp::EXTLLVM::EE->addModule(std::move(newModule));
    extemp::EXTLLVM::EE->finalizeObject();
    return modulePtr;
}
} // SchemeFFI
} // extemp

