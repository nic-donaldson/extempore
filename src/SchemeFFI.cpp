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
    using namespace llvm;

    // Create an LLVM module to put our function into
    legacy::PassManager *const PM = extemp::EXTLLVM::PM;
    legacy::PassManager *const PM_NO = extemp::EXTLLVM::PM_NO;

    SMDiagnostic pa;

    // First time entry
    // sLoadedInitialBitcodeAndSymbols == false
    // sInlineString == ""
    // sInlineBitcode == ""
    // sInlineSyms is empty

    // First time exit / second time entry
    // sLoadedInitialBitcodeAndSymbols == true
    // sInlineString == runtime/bitcode.ll contents
    // sInlineBitcode == ""
    // sInlineSyms has symbols from bitcode.ll and inline.ll

    // Second time exit / third time entry
    // inlinestring -> newmodule -> sinlinebitcode
    // sInlineString == runtime/inline.ll contents (loaded for a second time?)
    // sInlineBitcode == bitcode for runtime/bitcode.ll

    // The first time we call jitCompile we need to load SHARE/runtime/bitcode.ll
    // because it is prepended to every module before JITing
    static bool sLoadedInitialBitcodeAndSymbols(false);
    static std::string sInlineDotLLString;
    static std::string sBitcodeDotLLString;

    static std::string sInlineString;
    static std::string sInlineBitcode;
    static std::unordered_set<std::string> sInlineSyms;

    if (sLoadedInitialBitcodeAndSymbols == false) {
        sInlineDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll");
        sBitcodeDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll");

        insertMatchingSymbols(sBitcodeDotLLString, sGlobalSymRegex, sInlineSyms);
        insertMatchingSymbols(sInlineDotLLString, sGlobalSymRegex, sInlineSyms);

        sLoadedInitialBitcodeAndSymbols = true;
    }

    // sInlineBitcode serves a dual purpose here just like sInlineString did so
    // we should introduce a new variable

    // on the first run this will be true
    // on the second run too I think
    static bool first(true);
    if (sInlineBitcode.empty() && !first) {
      // need to avoid parsing the types twice

      // first time around this is true
      // second time around this is false
      auto newModule(
          parseAssemblyString(sBitcodeDotLLString, pa, getGlobalContext()));

      if (!newModule) {
        std::cout << pa.getMessage().str() << std::endl;
        abort();
      }

      llvm::raw_string_ostream bitstream(sInlineBitcode);
      llvm::WriteBitcodeToFile(newModule.get(), bitstream);

      sInlineString = sInlineDotLLString;
      // sInlineString held bitcode.ll but now it holds inline.ll ?
      // why not just use two strings
    }
    first = false;

    std::unordered_set<std::string> symbols;
    insertMatchingSymbols(asmcode, sGlobalSymRegex, symbols);

    std::unordered_set<std::string> ignoreSyms;
    insertMatchingSymbols(asmcode, sDefineSymRegex, ignoreSyms);

    std::string declarations;
    llvm::raw_string_ostream dstream(declarations);
    for (auto iter = symbols.begin(); iter != symbols.end(); ++iter) {
        const char* sym(iter->c_str());
        if (sInlineSyms.find(sym) != sInlineSyms.end() || ignoreSyms.find(sym) != ignoreSyms.end()) {
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

    std::unique_ptr<llvm::Module> newModule;
    if (!sInlineBitcode.empty()) {
        auto modOrErr(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));
        if (likely(modOrErr)) {
            newModule = std::move(modOrErr.get());
            asmcode = sInlineString + dstream.str() + asmcode; // at this point in time I think sInlineString holds inline.ll
            if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {
std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n" << std::endl;
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

        // Probably shouldn't be unwrapping a unique_ptr here
        // but we can think about that another time
        EXTLLVM::runPassManager(newModule.get());
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

