#include "llvm/IR/Module.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"

#include <EXTLLVM2.h>
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

static const std::string inlineDotLLString() {
  static const std::string sInlineDotLLString(
    fileToString(UNIV::SHARE_DIR + "/runtime/inline.ll"));

  return sInlineDotLLString;
}

static const std::string bitcodeDotLLString(){
  static const std::string sBitcodeDotLLString(
    fileToString(UNIV::SHARE_DIR + "/runtime/bitcode.ll"));

  return sBitcodeDotLLString;
}

static std::string loadBitcode()
{
  std::string bitcode;
  // will print and abort on failure
  auto mod(extemp::EXTLLVM2::parseAssemblyString(bitcodeDotLLString()));
  extemp::EXTLLVM2::writeBitcodeToFile(mod.get(), bitcode);
  return bitcode;
}

static const std::string bitcode()
{
  static std::string sInlineBitcode(loadBitcode());
  return sInlineBitcode;
}

static std::unordered_set<std::string> loadInlineSyms()
{
  std::unordered_set<std::string> bitcodeLLGSyms =
    extemp::EXTLLVM2::globalSyms(bitcodeDotLLString());

  std::unordered_set<std::string> inlineLLGSyms =
    extemp::EXTLLVM2::globalSyms(inlineDotLLString());

  // std::unordered_set<>::merge is C++17 so this will
  // do for now
  std::unordered_set<std::string> sInlineSyms;
  std::copy(bitcodeLLGSyms.begin(),
            bitcodeLLGSyms.end(),
            std::inserter(sInlineSyms, sInlineSyms.begin()));
  // TODO: does this work? can I use .begin() twice like this?
  std::copy(inlineLLGSyms.begin(),
            inlineLLGSyms.end(),
            std::inserter(sInlineSyms, sInlineSyms.begin()));

  return sInlineSyms;
}

static const std::unordered_set<std::string> inlineSyms()
{
  static const std::unordered_set<std::string> syms(loadInlineSyms());
  return syms;
}

static llvm::Module *jitCompile(std::string asmcode) {
  const std::string declarations =
    extemp::EXTLLVM2::globalDecls(asmcode, inlineSyms());

  std::unique_ptr<llvm::Module> newModule(extemp::EXTLLVM2::parseBitcodeFile(bitcode()));
  llvm::SMDiagnostic pa;

  if (likely(newModule)) {
    // so every module but init.ll gets prepended with bitcode.ll,
    // inline.ll, and any global declarations?
    asmcode = inlineDotLLString() + declarations + asmcode;
    if (extemp::EXTLLVM2::parseAssemblyInto(asmcode, *newModule, pa)) {
      std::cout << "**** DECL ****"
                << std::endl
                << declarations
                << "**** ENDDECL ****"
                << std::endl;
      newModule.reset();
    }
  }

  if (unlikely(!newModule)) {
    pa.print("LLVM IR", llvm::outs());
    return nullptr;
  }

  if (extemp::EXTLLVM2::verifyModule(*newModule)) {
    std::cout << "Invalid LLVM IR" << std::endl;
    return nullptr;
  }

  if (unlikely(!extemp::UNIV::ARCH.empty())) {
    newModule->setTargetTriple(extemp::UNIV::ARCH);
  }

  // Probably shouldn't be unwrapping a unique_ptr here
  // but we can think about that another time
  llvm::Module *modulePtr = extemp::EXTLLVM2::addModule(std::move(newModule));

  return modulePtr;
}

pointer jitCompileIRString(scheme *Scheme, pointer Args) {
  static bool isThisInitDotLL(true);

  llvm::Module* modulePtr = nullptr;
  if (isThisInitDotLL) {
    modulePtr = extemp::EXTLLVM2::jitCompile(string_value(pair_car(Args)));
    isThisInitDotLL = false;
  } else {
    modulePtr = jitCompile(string_value(pair_car(Args)));
  }

  if (!modulePtr) {
    return Scheme->F;
  }
  return mk_cptr(Scheme, modulePtr);
}

pointer get_function(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_cptr(Scheme, const_cast<llvm::Function*>(func));
}

pointer get_globalvar(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM2::GlobalMap::getGlobalVariable(string_value(pair_car(Args))));
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
    auto newM(extemp::EXTLLVM2::parseAssemblyString2(assm, pa));
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
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
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
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
    return (func && func->isVarArg()) ? Scheme->T : Scheme->F;
}


pointer get_function_type(scheme* Scheme, pointer Args)
{
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
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
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
    if (!func) {
        return Scheme->F;
    }
    return mk_integer(Scheme, func->getCallingConv());
}
pointer get_global_variable_type(scheme* Scheme, pointer Args)
{
    auto var(extemp::EXTLLVM2::GlobalMap::getGlobalVariable(string_value(pair_car(Args))));
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
    extemp::EXTLLVM2::MutexGuard locked;
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
    auto func(extemp::EXTLLVM2::GlobalMap::getFunction(string_value(pair_car(Args))));
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
    fout << irStr; // ss.str();
    fout.close();
#else
    if (!extemp::EXTLLVM2::writeBitcodeToFile2(m, filename)) {
         return Scheme->F;
    }
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
