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

pointer get_struct_size(scheme* Scheme, pointer Args)
{
    const std::string struct_type_str(string_value(pair_car(Args)));
    long size = extemp::EXTLLVM2::getStructSize(struct_type_str);
    if (size == -1) {
      return Scheme->F;
    }

    return mk_integer(Scheme, size);
}

pointer get_named_struct_size(scheme* Scheme, pointer Args)
{
    const std::string name(string_value(pair_car(Args)));
    long size = extemp::EXTLLVM2::getNamedStructSize(name);
    if (size == -1) {
        return Scheme->F;
    }

    return mk_integer(Scheme, size);
}

pointer get_function_args(scheme* Scheme, pointer Args)
{
    const std::string fname(string_value(pair_car(Args)));
    const std::vector<std::string> args(extemp::EXTLLVM2::getFunctionArgs(fname));

    if (args.empty()) {
        return Scheme->F;
    }

    pointer str = mk_string(Scheme, args[0].c_str());
    pointer p = cons(Scheme, str, Scheme->NIL);
    for (auto iter = ++args.begin(); iter != args.end(); ++iter) {
        const auto& arg = *iter;
        {
            EnvInjector injector(Scheme, p);
            str = mk_string(Scheme, arg.c_str());
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
    const std::string fname(string_value(pair_car(Args)));
    const std::string type = extemp::EXTLLVM2::getFunctionType(fname);

    if (type.compare("") == 0) {
        return Scheme->F;
    }
    return mk_string(Scheme, type.c_str());
}

pointer get_function_calling_conv(scheme* Scheme, pointer Args)
{
    const std::string fname(string_value(pair_car(Args)));
    const long long cc = extemp::EXTLLVM2::getFunctionCallingConv(fname);
    if (cc == -1) {
        return Scheme->F;
    }
    return mk_integer(Scheme, extemp::EXTLLVM2::getFunctionCallingConv(fname));
}

pointer get_global_variable_type(scheme* Scheme, pointer Args)
{
    const std::string vname(string_value(pair_car(Args)));
    const std::string type = extemp::EXTLLVM2::getGlobalVariableType(vname);
    if (type == "") {
        return Scheme->F;
    }

    return mk_string(Scheme, type.c_str());
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
    const std::string fname(string_value(pair_car(Args)));
    bool res = EXTLLVM2::removeFunctionByName(fname);
    if (!res) {
        return Scheme->F;
    } else {
        return Scheme->T;
    }
}

pointer remove_global_var(scheme* Scheme, pointer Args)
{
    const std::string vname(string_value(pair_car(Args)));
    if (EXTLLVM2::removeGlobalVarByName(vname)) {
        return Scheme->T;
    }
    return Scheme->F;
}

pointer erase_function(scheme* Scheme, pointer Args)
{
    const std::string fname(string_value(pair_car(Args)));
    if (EXTLLVM2::eraseFunctionByName(fname)) {
        return Scheme->T;
    }
    return Scheme->F;
}

pointer llvm_call_void_native(scheme* Scheme, pointer Args)
{
    const std::string fname(string_value(pair_car(Args)));

    void* p = EXTLLVM2::findVoidFunctionByName(fname);
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
    void* func_ptr = cptr_value(pair_car(Args));
    Args = pair_cdr(Args);
    unsigned lgth = list_length(Scheme, Args);

    int i = 0;
    std::vector<EXTLLVM2::EARG> args;
    args.reserve(lgth);

    while (Args != Scheme->NIL) {
        EXTLLVM2::EARG arg;
        pointer p = car(Args);
        Args = cdr(Args);
        if (is_integer(p)) {
            arg.tag = EXTLLVM2::ArgType::INT;
            arg.int_val = ivalue(p);
        } else if (is_real(p)) {
            arg.tag = EXTLLVM2::ArgType::DOUBLE;
            arg.double_val = rvalue(p);
        } else if (is_string(p)) {
            arg.tag = EXTLLVM2::ArgType::STRING;
            arg.string = string_value(p);
        } else if (is_cptr(p)) {
            arg.tag = EXTLLVM2::ArgType::PTR;
            arg.ptr = cptr_value(p);
        } else if (unlikely(is_closure(p))) {
            printf("Bad argument at index %i you can't pass in a scheme closure.\n", i);
            return Scheme->F;
        } else {
            printf("Bad argument at index %i\n", i);
            return Scheme->F;
        }
        args.push_back(arg);
    }

    std::reverse(args.begin(), args.end());
    EXTLLVM2::Result res(EXTLLVM2::callCompiled(func_ptr, lgth, args));
    if (res.tag == EXTLLVM2::ResultType::BAD) {
        return Scheme->F;
    } else {
        switch(res.val.tag) {
        case EXTLLVM2::ArgType::DOUBLE:
            return mk_real(Scheme, res.val.double_val);
        case EXTLLVM2::ArgType::INT:
            return mk_integer(Scheme, res.val.int_val);
        case EXTLLVM2::ArgType::PTR:
            return mk_cptr(Scheme, res.val.ptr);
        case EXTLLVM2::ArgType::VOID:
            return Scheme->T;
        default:
            return Scheme->F;
        }
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
    EXTLLVM2::printAllModules();
    return Scheme->T;
}

pointer printLLVMFunction(scheme* Scheme, pointer Args)
{
    auto fname(string_value(pair_car(Args)));
    EXTLLVM2::printLLVMFunction(fname);
    return Scheme->T;
}

pointer llvm_print_all_closures(scheme* Scheme, pointer Args) // TODO
{
    char* x = string_value(pair_car(Args));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "_.*");
    const std::string rgx_s(rgx);
    EXTLLVM2::printAllClosures(rgx_s);
    return Scheme->T;
}

pointer llvm_print_closure(scheme* Scheme, pointer Args) // TODO
{
    const std::string fname(string_value(pair_car(Args)));
    EXTLLVM2::printClosure(fname);
    return Scheme->T;
}

pointer llvm_closure_last_name(scheme* Scheme, pointer Args)
{
    auto x(string_value(pair_car(Args)));
    char rgx[1024];
    strcpy(rgx, x);
    strcat(rgx, "__[0-9]*");

    const char* last_name(EXTLLVM2::closureLastName(std::string(rgx)));

    if (last_name) {
        return mk_string(Scheme, last_name);
    }
    return Scheme->F;
}

pointer bind_symbol(scheme* Scheme, pointer Args)
{
    auto library(cptr_value(pair_car(Args)));
    const std::string sym(string_value(pair_cadr(Args)));
    if(EXTLLVM2::bindSymbol(sym, library)) {
        return Scheme->T;
    }
    return Scheme->F;
}


pointer update_mapping(scheme* Scheme, pointer Args)
{
    const std::string sym(string_value(pair_car(Args)));
    auto ptr(cptr_value(pair_cadr(Args)));

    return mk_cptr(Scheme, EXTLLVM2::updateMapping(sym, ptr));
}

static char tmp_str_a[1024];
static char tmp_str_b[4096];
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
    auto tt(extemp::EXTLLVM2::getTypeByName(std::string(name, len)));
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
