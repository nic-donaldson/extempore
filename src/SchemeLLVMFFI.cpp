#include "llvm/AsmParser/Parser.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MutexGuard.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"

#include <EXTLLVM2.h>
#include <LLVMIRCompilation.h>
#include <EXTLLVMGlobalMap.h>
#include <Scheme.h>
#include <SchemeLLVMFFI.h>
#include <SchemePrivate.h>

#include <fstream>
#include <sstream>
#include <iostream>

#ifndef _WIN32
#include <dlfcn.h>
#endif

#define pair_cadr(p) pair_car(pair_cdr(p))

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

static LLVMIRCompilation IRCompiler;

static void
loadInitialBitcodeAndSymbols(std::string &sInlineDotLLString,
                             std::unordered_set<std::string> &sInlineSyms,
                             std::string &sInlineBitcode) {
  llvm::SMDiagnostic pa;

  sInlineDotLLString = fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll");
  const std::string bitcodeDotLLString =
      fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll");
  LLVMIRCompilation::insertMatchingSymbols(
      bitcodeDotLLString, extemp::LLVMIRCompilation::globalSymRegex,
      sInlineSyms);
  LLVMIRCompilation::insertMatchingSymbols(
      sInlineDotLLString, extemp::LLVMIRCompilation::globalSymRegex,
      sInlineSyms);

  // put bitcode.ll -> sInlineBitcode
  // will print error and abort on failure
  auto newModule(extemp::EXTLLVM2::parseAssemblyString(bitcodeDotLLString));

  llvm::raw_string_ostream bitstream(sInlineBitcode);
  llvm::WriteBitcodeToFile(newModule.get(), bitstream);
}

static llvm::Module *jitCompile(std::string asmcode) {
  // the first time we call jitCompile it's init.ll which requires
  // special behaviour
  static bool isThisInitDotLL(true);

  static bool sLoadedInitialBitcodeAndSymbols(false);
  static std::string sInlineDotLLString;
  static std::string sInlineBitcode; // contains compiled bitcode from bitcode.ll
  static std::unordered_set<std::string> sInlineSyms;

  if (sLoadedInitialBitcodeAndSymbols == false) {
    loadInitialBitcodeAndSymbols(sInlineDotLLString, sInlineSyms,
                                 sInlineBitcode);
    sLoadedInitialBitcodeAndSymbols = true;
  }

  const std::string declarations =
      IRCompiler.necessaryGlobalDeclarations(asmcode, sInlineSyms);

  // std::cout << "**** DECL ****\n" << dstream.str() << "**** ENDDECL ****\n"
  // << std::endl;

  std::unique_ptr<llvm::Module> newModule = nullptr;

  if (!isThisInitDotLL) {
    std::unique_ptr<llvm::Module> inNewModule = nullptr;
    llvm::SMDiagnostic pa;

    if (!isThisInitDotLL) {
      // module from bitcode.ll
      auto module(extemp::EXTLLVM2::parseBitcodeFile(sInlineBitcode));

      if (likely(module)) {
        inNewModule = std::move(module);
        // so every module but init.ll gets prepended with bitcode.ll,
        // inline.ll, and any global declarations?
        asmcode = sInlineDotLLString + declarations + asmcode;
        if (extemp::EXTLLVM2::parseAssemblyInto(asmcode,
                              *inNewModule, pa)) {
          std::cout << "**** DECL ****\n"
                    << declarations
                    << "**** ENDDECL ****\n"
                    << std::endl;
          inNewModule.reset();
        }
      }
    }

    if (unlikely(!inNewModule)) {
      pa.print("LLVM IR", llvm::outs());
      return nullptr;
    }

    newModule = std::move(inNewModule);
  }

  if (isThisInitDotLL) {
    llvm::SMDiagnostic pa;
    std::unique_ptr<llvm::Module> inNewModule(extemp::EXTLLVM2::parseAssemblyString2(asmcode, pa));

    if (unlikely(!inNewModule)) {
      // std::cout << "**** CODE ****\n" << asmcode << " **** ENDCODE ****" <<
      // std::endl; std::cout << pa.getMessage().str() << std::endl <<
      // pa.getLineNo() << std::endl;
      pa.print("LLVM IR", llvm::outs());
      return nullptr;
    }

    newModule = std::move(inNewModule);
  }

  if (verifyModule(*newModule)) { // i can't believe this function returns true
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
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::Function*>(func));
}

pointer get_globalvar(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM::GlobalMap::getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::GlobalVariable*>(var));
}

static uint64_t string_hash(const char* str)
{
    uint64_t result(0);
    unsigned char c;
    while((c = *(str++))) {
        result = result * 33 + uint8_t(c);
    }
    return result;
}


pointer get_struct_size(scheme* Scheme, pointer Args)
{
    char* struct_type_str = string_value(pair_car(Args));
    unsigned long long hash = string_hash(struct_type_str);
    char name[128];
    sprintf(name, "_xtmT%lld", hash);
    char assm[1024];
    sprintf(assm, "%%%s = type %s", name, struct_type_str);

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

pointer get_named_struct_size(scheme* Scheme, pointer Args)
{
    auto type(EXTLLVM2::getTypeByName(string_value(pair_car(Args))));
    if (!type) {
        return Scheme->F;
    }
    return mk_integer(Scheme, EXTLLVM2::getNamedStructSize(type));
}

static char tmp_str_a[1024];
static char tmp_str_b[4096];

pointer get_function_args(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
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

pointer get_function_varargs(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
    return (func && func->isVarArg()) ? Scheme->T : Scheme->F;
}


pointer get_function_type(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    func->getFunctionType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}
pointer get_function_calling_conv(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_integer(Scheme, func->getCallingConv());
}
pointer get_global_variable_type(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM::GlobalMap::getGlobalVariable(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    std::string typestr;
    llvm::raw_string_ostream ss(typestr);
    var->getType()->print(ss);
    return mk_string(Scheme, ss.str().c_str());
}

pointer get_function_pointer(scheme* Scheme, pointer Args)
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

pointer remove_function(scheme* Scheme, pointer Args)
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

pointer remove_global_var(scheme* Scheme, pointer Args)
{
    auto var(EXTLLVM2::FindGlobalVariableNamed(string_value(pair_car(Args))));
    if (!var) {
        return Scheme->F;
    }
    var->dropAllReferences();
    var->removeFromParent();
    return Scheme->T;
}

pointer erase_function(scheme* Scheme, pointer Args)
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

pointer llvm_call_void_native(scheme* Scheme, pointer Args)
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

// setting this define should make call_compiled thread safe BUT ...
// also extremely SLOW !
#define LLVM_EE_LOCK

pointer call_compiled(scheme* Scheme, pointer Args)
{
#ifdef LLVM_EE_LOCK
    llvm::MutexGuard locked(EXTLLVM2::getEEMutex());
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
    llvm::GenericValue gv = EXTLLVM2::runFunction(func, fargs);
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
pointer llvm_convert_float_constant(scheme* Scheme, pointer Args)
{
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    return mk_string(Scheme, extemp::EXTLLVM2::float_utohexstr(floatin).c_str());
}

pointer llvm_convert_double_constant(scheme* Scheme, pointer Args)
{
    static_assert(sizeof(double) == sizeof(uint64_t), "sizeof(double) must be 8 bytes");
    char* floatin = string_value(pair_car(Args));
    if (floatin[1] == 'x') {
        return pair_car(Args);
    }
    return mk_string(Scheme, extemp::EXTLLVM2::double_utohexstr(floatin).c_str());
}

int64_t LLVM_COUNT = 0;
pointer llvm_count(scheme* Scheme, pointer)
{
    return mk_integer(Scheme, LLVM_COUNT);
}

pointer llvm_count_set(scheme* Scheme, pointer Args)
{
    LLVM_COUNT = ivalue(pair_car(Args));
    return llvm_count(Scheme, Args);
}

pointer llvm_count_inc(scheme* Scheme, pointer Args)
{
    ++LLVM_COUNT;
    return llvm_count(Scheme, Args);
}

pointer callClosure(scheme* Scheme, pointer Args)
{
    uint32_t** closure = reinterpret_cast<uint32_t**>(cptr_value(pair_car(Args)));
    auto fptr(reinterpret_cast<int64_t (*)(void*, int64_t)>(closure[0]));
    return mk_integer(Scheme, (*fptr)(closure[0], ivalue(pair_cadr(Args))));
}

pointer llvm_print_all_modules(scheme* Scheme, pointer) // TODO
{
    for (auto module : EXTLLVM2::getModules()) {
        std::string str;
        llvm::raw_string_ostream ss(str);
        ss << *module;
        printf("\n---------------------------------------------------\n%s", ss.str().c_str());
    }
    return Scheme->T;
}

pointer printLLVMFunction(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM::GlobalMap::getFunction(string_value(pair_car(Args))));
    std::string str;
    llvm::raw_string_ostream ss(str);
    ss << *func;
    puts(ss.str().c_str());
    return Scheme->T;
}

pointer llvm_print_all_closures(scheme* Scheme, pointer Args) // TODO
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

pointer llvm_print_closure(scheme* Scheme, pointer Args) // TODO
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

pointer llvm_closure_last_name(scheme* Scheme, pointer Args)
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
pointer bind_symbol(scheme* Scheme, pointer Args)
{
    auto library(cptr_value(pair_car(Args)));
    auto sym(string_value(pair_cadr(Args)));

#ifdef _WIN32
    auto ptr(reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(library), sym)));
#else
    auto ptr(dlsym(library, sym));
#endif
    if (likely(ptr)) {
        extemp::EXTLLVM2::addGlobalMappingUnderEELock(sym, reinterpret_cast<uint64_t>(ptr));
        return Scheme->T;
    }
    return Scheme->F;
}
pointer update_mapping(scheme* Scheme, pointer Args)
{
    auto sym(string_value(pair_car(Args)));
    auto ptr(cptr_value(pair_cadr(Args)));

    auto oldval(EXTLLVM2::addGlobalMappingUnderEELock(sym, reinterpret_cast<uintptr_t>(ptr)));
    return mk_cptr(Scheme, reinterpret_cast<void*>(oldval));
}

pointer get_named_type(scheme* Scheme, pointer Args)
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
    auto tt(EXTLLVM2::getTypeByName(std::string(name, len).c_str()));
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

pointer export_llvmmodule_bitcode(scheme* Scheme, pointer Args)
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

pointer llvm_disasm(scheme* Scheme, pointer Args)
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
    return mk_string(Scheme, extemp::EXTLLVM2::llvm_disassemble(fptr, syntax));
}

} // namespace LLVM
} // namespace SchemeFFI
} // namespace extemp
