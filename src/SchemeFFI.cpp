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
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm-c/Core.h"
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
#include "llvm/Bitcode/BitcodeReader.h"

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
//#include <unistd.h>
#include <EXTMutex.h>
#include <EXTLLVM.h>
namespace extemp { namespace SchemeFFI {
static llvm::Module* jitCompile(const std::string& String);
static llvm::Module* jitCompileORC(const std::string& llvmir_str);
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

static long long llvm_emitcounter = 0;

// Returns type as string, with the first '=' removed if there is one
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
    
    // TODO big hack delete me
    std::regex e("(^%.*?)(\\.\\d+)(\\*$)");
    
    //return str;
    
    std::string clean_str = std::regex_replace(str, e, "$1$3");
    return clean_str;
}

static std::regex sGlobalSymRegex("[ \t]@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize);
static std::regex sDefineSymRegex("define[^\\n]+@([-a-zA-Z$._][-a-zA-Z$._0-9]*)", std::regex::optimize | std::regex::ECMAScript);

static llvm::Module* jitCompileORC(const std::string& llvmir_str) {
    // TODO delete this bit
    std::string mzone_declaration = "%mzone = type {i8*, i64, i64, i64, i8*, %mzone*}\n"
                                    "%clsvar = type {i8*, i32, i8*, %clsvar*}\n";

    std::string module_ir = mzone_declaration + llvmir_str;
    
    // Create a module name
    std::stringstream module_name_ss;
    module_name_ss << "xtmmodule_" << ++llvm_emitcounter;
    std::string module_name = module_name_ss.str();
    
    std::cout << "New module: " << module_name << std::endl;
    
    llvm::SMDiagnostic llvm_error;
    std::unique_ptr<llvm::Module> new_module = parseAssemblyString(module_ir, llvm_error, extemp::EXTLLVM::TheContext);
    if (!new_module) {
        std::cout << "Error compiling module " << module_name << std::endl;
        llvm_error.print(module_name.c_str(), llvm::outs());
        return nullptr;
    } else {
        std::cout << "Compiled module " << module_name << " successfully!" << std::endl;
        return new_module.get();
    }
    
    return nullptr;
}

static llvm::Module* jitCompile(const std::string& String)
{
    // Create some module to put our function in
    using namespace llvm;
    legacy::PassManager* PM = extemp::EXTLLVM::PM;
    legacy::PassManager* PM_NO = extemp::EXTLLVM::PM_NO;

    char modname[256];
    sprintf(modname, "xtmmodule_%lld", ++llvm_emitcounter);

    std::string asmcode(String);
    SMDiagnostic pa;

    // Build up a string of symbols to insert into every module ?
    static std::string sInlineString; // This is a hack for now, but it *WORKS*
    static std::string sInlineBitcode;
    static std::unordered_set<std::string> sInlineSyms;

    // Pull out the symbol name from any @symbol in bitcode.ll or inline.ll and add it to sInlineSyms
    if (sInlineString.empty()) {
        {
            std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/bitcode.ll");
            std::stringstream inString;
            inString << inStream.rdbuf();
            sInlineString = inString.str();
        }
        std::copy(std::sregex_token_iterator(sInlineString.begin(), sInlineString.end(), sGlobalSymRegex, 1),
                std::sregex_token_iterator(), std::inserter(sInlineSyms, sInlineSyms.begin()));
        {
            std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/inline.ll");
            std::stringstream inString;
            inString << inStream.rdbuf();
            std::string tString = inString.str();
            std::copy(std::sregex_token_iterator(tString.begin(), tString.end(), sGlobalSymRegex, 1),
                    std::sregex_token_iterator(), std::inserter(sInlineSyms, sInlineSyms.begin()));
        }
    }

    if (sInlineBitcode.empty()) {
        // need to avoid parsing the types twice
        static bool first(true);
        if (!first) {
            // Get LLVM bitcode from sInlineString -> sInlineBitcode
            // sInlineString contains bitcode.ll at this point
            // so after this, sInlineBitcode contains bitcode generated from bitcode.ll
            // and sInlineString then has inline.ll
            auto newModule (parseAssemblyString(sInlineString, pa, EXTLLVM::TheContext));
            if (newModule) {
                llvm::raw_string_ostream bitstream(sInlineBitcode);
                llvm::WriteBitcodeToFile(newModule.get(), bitstream);

                // sInlineString will from now on be added to the start of any module we compile in the future
                std::ifstream inStream(UNIV::SHARE_DIR + "/runtime/inline.ll");
                std::stringstream inString;
                inString << inStream.rdbuf();
                sInlineString = inString.str();
            } else {
                // Something went wrong, print out an error message
                std::cout << pa.getMessage().str() << std::endl;
                abort();
            }
        } else {
            first = false;
        }
    }

    std::unique_ptr<llvm::Module> newModule;

    // Pull @symbol into symbols
    std::vector<std::string> symbols;
    std::copy(std::sregex_token_iterator(asmcode.begin(), asmcode.end(), sGlobalSymRegex, 1),
              std::sregex_token_iterator(), std::inserter(symbols, symbols.begin()));

    // Remove duplicate symbols
    std::sort(symbols.begin(), symbols.end());
    auto end(std::unique(symbols.begin(), symbols.end()));

    // Add 'define @symbol's to ignoreSyms
    std::unordered_set<std::string> ignoreSyms;
    std::copy(std::sregex_token_iterator(asmcode.begin(), asmcode.end(), sDefineSymRegex, 1),
              std::sregex_token_iterator(), std::inserter(ignoreSyms, ignoreSyms.begin()));

    // We need to declare external functions and values so that they're accessible
    // in our module
    std::string declarations;
    llvm::raw_string_ostream dstream(declarations);
    for (auto iter = symbols.begin(); iter != end; ++iter) {
        const char* sym(iter->c_str());
        if (sInlineSyms.find(sym) != sInlineSyms.end() || ignoreSyms.find(sym) != ignoreSyms.end()) {
            // If the symbol is already in sInlineSyms, or we're ignoring it, skip
            // If it's in sInlineSyms ,we'll be including it anyway from inline.ll
            continue;
        }

        // Pull llvm::GlobalValue* from our globals map if it's in there, if not just skip
        // The first time around, nothing will be in the globals map, the symbols will be inserted
        // when we call EXTLLVM::addModule
        auto gv = extemp::EXTLLVM::getGlobalValue(sym);
        if (!gv) {
            continue;
        }
        auto func(llvm::dyn_cast<llvm::Function>(gv));
        if (func) {
            // TODO remove this
            if (strcmp(sym, "llvm_zone_malloc")  == 0) {
                std::cerr << "hello" << std::endl;
            }
            
            // The symbol happens to be a function
            // We're constructing a function prototype string in LLVM IR here
            // Is there not a function that does this already?
            const std::string rtype = SanitizeType(func->getReturnType());
            dstream << "declare " << rtype << " @" << sym << " (";

            bool first(true);
            for (const auto& arg : func->args()) {
                if (!first) {
                    dstream << ", ";
                } else {
                    first = false;
                }
                dstream << SanitizeType(arg.getType());
            }
            if (func->isVarArg()) {
                dstream << ", ...";
            }
            dstream << ")\n";
        } else {
            // gv is not a function, it is a global value so we just declare that it exists
            auto str(SanitizeType(gv->getType()));
            dstream << '@' << sym << " = external global " << str.substr(0, str.length() - 1) << '\n';
        }
    }

    if (!sInlineBitcode.empty()) {
        auto modOrErr(parseBitcodeFile(llvm::MemoryBufferRef(sInlineBitcode, "<string>"), EXTLLVM::TheContext));
        if (likely(modOrErr)) {
            newModule = std::move(modOrErr.get());

            // TODO delete this
            std::string d = dstream.str();

            //asmcode = sInlineString + dstream.str() + asmcode;
            asmcode = sInlineString + d + asmcode;
            
            if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"), *newModule, pa)) {                
                newModule.reset();
            }
        }
    } else {
        // Only happens once
        newModule = parseAssemblyString(asmcode, pa, EXTLLVM::TheContext);
    }
    if (newModule) {
        if (unlikely(!extemp::UNIV::ARCH.empty())) {
            newModule->setTargetTriple(extemp::UNIV::ARCH);
        }
        if (EXTLLVM::OPTIMIZE_COMPILES) {
            PM->run(*newModule);
        } else {
            PM_NO->run(*newModule);
        }
    }
    
    if (unlikely(!newModule))
    {
        std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" << std::endl;
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

