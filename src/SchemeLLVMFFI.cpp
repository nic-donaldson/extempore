#include <EXTLLVM2.h>
#include <LLVMIRCompilation.h>
#include <EXTLLVMGlobalMap.h>
#include <Scheme.h>
#include <SchemeLLVMFFI.h>
#include <SchemePrivate.h>

#include "llvm/AsmParser/Parser.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"

#include <fstream>
#include <sstream>
#include <iostream>

namespace extemp {
namespace SchemeFFI {
namespace LLVM {
pointer optimizeCompiles(scheme *Scheme, pointer Args) {
  EXTLLVM2::setOptimize((pair_car(Args) == Scheme->T));
  return Scheme->T;
}

static std::string fileToString(const std::string &fileName) {
  std::ifstream inStream(fileName);
  std::stringstream inString;
  inString << inStream.rdbuf();
  return inString.str();
}

static llvm::Module *jitCompile(const std::string asmcode);
static LLVMIRCompilation IRCompiler;

static void
loadInitialBitcodeAndSymbols(std::string &sInlineDotLLString,
                             std::unordered_set<std::string> &sInlineSyms,
                             std::string &sInlineBitcode) {
  using namespace llvm;
  SMDiagnostic pa;

  sInlineDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll");
  const std::string bitcodeDotLLString =
      fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll");
  LLVMIRCompilation::insertMatchingSymbols(bitcodeDotLLString,
                        extemp::LLVMIRCompilation::globalSymRegex, sInlineSyms);
  LLVMIRCompilation::insertMatchingSymbols(sInlineDotLLString,
                        extemp::LLVMIRCompilation::globalSymRegex, sInlineSyms);

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

static llvm::Module *jitCompile(std::string asmcode) {
  // so the first file that comes through is runtime/init.ll
  // it begins with
  // %mzone = type { i8*, i64, i64, i64, i8*, %mzone* rbrace if I actually type
  // the brace emacs decides to reindent everything i love computers std::cout
  // << asmcode << std::endl; std::cout <<
  // "----------------------------------------------------------" << std::endl;

  using namespace llvm;

  // the first time we call jitCompile it's init.ll which requires
  // special behaviour
  static bool isThisInitDotLL(true);

  static bool sLoadedInitialBitcodeAndSymbols(false);
  static std::string sInlineDotLLString;
  static std::string
      sInlineBitcode; // contains compiled bitcode from bitcode.ll
  static std::unordered_set<std::string> sInlineSyms;

  if (sLoadedInitialBitcodeAndSymbols == false) {
    loadInitialBitcodeAndSymbols(sInlineDotLLString, sInlineSyms,
                                 sInlineBitcode);
    sLoadedInitialBitcodeAndSymbols = true;
  }

  // contents of sInlineSyms:
  /*
is_integer, llvm_zone_mark_size, llvm_zone_mark, llvm_zone_create,
llvm_zone_create_extern, llvm_peek_zone_stack, llvm_peek_zone_stack_extern,
ascii_text_color, llvm_now, is_cptr_or_str, is_cptr, is_real, is_type, sscanf,
fscanf, ftoui64, ftoi16, dtoi1, i32toui64, ftod, is_integer_extern, i16toi1,
i64toi32, i16toi8, sprintf, ftoi8, i64toi16, i32toptr, dtoui8, i16toi32,
i8toui64, fprintf, ftoi1, i1toi16, ftoui32, llvm_zone_ptr_set_size, is_string,
ftoi64, printf, i8toi1, i64tod, i32toi1, impc_null, impc_false, i64toi8,
ui64tof, impc_true, dtoi32, i8toi64, ptrtoi32, i1toi8, i64toi1, ftoi32,
i16toui64, ui8tod, i32toi64, i1toi64, dtof, i8toi16, ftoui16,
llvm_push_zone_stack, i32toi8, i32toi16, ftoui1, ui1tod, i64tof, ptrtoi64,
new_address_table, i8toui32, i32tof, i8tof, i1tof, ui32tof, ui16tof, ui8tof,
ui1tof, dtoui32, dtoi64, i16tod, dtoi16, i1toi32, dtoi8,
ascii_text_color_extern, i16toui32, dtoui64, i1tod, fp80ptrtod, dtoui16, dtoui1,
i32tod, ftoui8, i8toi32, i8tod, llvm_zone_reset, TIME, i16toi64, ui64tod,
i16tof, ui32tod, ui16tod, i64toptr, llvm_push_zone_stack_extern, ptrtoi16,
i16toptr


  for (const auto &sym : sInlineSyms) {
      std::cout << sym << ", ";
  }
  std::cout <<
"-------------------------------------------------------------------" <<
std::endl;

e.g. new_address_table is the first definition in inline.ll it appears as
@new_address_table which matches the globalsymregex we're using from llvm 3.8.0
docs: "LLVM identifiers come in two basic types: global and local. Global
identifiers (functions, global variables) begin with the '@' character."

so basically all the global syms, "@thing", appear in sInlineSyms

this is pretty rudimentary won't handle LLVM comments or linkage types e.g.
"private". should replace this with Module introspection/reflection

"LLVM programs are composed of Module‘s, each of which is a translation unit of
the input programs. Each module consists of functions, global variables, and
symbol table entries. Modules may be combined together with the LLVM linker,
which merges function (and global variable) definitions, resolves forward
declarations, and merges symbol table entries."
  */

  const std::string declarations =
      IRCompiler.necessaryGlobalDeclarations(asmcode, sInlineSyms);

  // std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n"
  // << std::endl;

  std::unique_ptr<llvm::Module> newModule = nullptr;
  SMDiagnostic pa;

  if (!isThisInitDotLL) {
    // module from bitcode.ll
    auto module(parseBitcodeFile(
        llvm::MemoryBufferRef(sInlineBitcode, "<string>"), getGlobalContext()));

    if (likely(module)) {
      newModule = std::move(module.get());
      // so every module but init.ll gets prepended with bitcode.ll, inline.ll,
      // and any global declarations?
      asmcode = sInlineDotLLString + declarations + asmcode;
      if (parseAssemblyInto(llvm::MemoryBufferRef(asmcode, "<string>"),
                            *newModule, pa)) {
        std::cout << "**** DECL ****\n"
                  << declarations << "**** ENDDECL ****\n"
                  << std::endl;
        newModule.reset();
      }
    }
  }

  if (isThisInitDotLL) {
    newModule = parseAssemblyString(asmcode, pa, getGlobalContext());
  }

  if (unlikely(!newModule)) {
    // std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" <<
    // std::endl; std::cout << pa.getMessage().str() << std::endl <<
    // pa.getLineNo() << std::endl;

    std::string errstr;
    llvm::raw_string_ostream ss(errstr);
    pa.print("LLVM IR", ss);
    printf("%s\n", ss.str().c_str());
    return nullptr;
  }

  static bool VERIFY_COMPILES = true;
  if (VERIFY_COMPILES &&
      verifyModule(*newModule)) { // i can't believe this function returns true
                                  // on an error
    std::cout << "\nInvalid LLVM IR\n";
    return nullptr;
  }

  if (unlikely(!extemp::UNIV::ARCH.empty())) {
    newModule->setTargetTriple(extemp::UNIV::ARCH);
  }

  // Probably shouldn't be unwrapping a unique_ptr here
  // but we can think about that another time
  llvm::Module *modulePtr = extemp::EXTLLVM2::addModule(std::move(newModule));

  isThisInitDotLL = false;

  return modulePtr;
}

pointer jitCompileIRString(scheme *Scheme, pointer Args) {
  auto modulePtr(jitCompile(string_value(pair_car(Args))));
  if (!modulePtr) {
    return Scheme->F;
  }
  return mk_cptr(Scheme, modulePtr);
}

pointer get_function(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::Function*>(func));
}


} // namespace LLVM
} // namespace SchemeFFI
} // namespace extemp
