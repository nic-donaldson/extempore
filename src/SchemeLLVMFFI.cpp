#include <EXTLLVM2.h>
#include <Scheme.h>
#include <SchemeLLVMFFI.h>
#include <SchemePrivate.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iterator>

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
  // will print and abort on failure
  return EXTLLVM2::IRToBitcode(bitcodeDotLLString());
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
    std::cout << "asmcode:" << std::endl << asmcode << std::endl;
    const std::string declarations =
        extemp::EXTLLVM2::globalDecls(asmcode, inlineSyms());

    std::cout << "declarations:" << std::endl << declarations << std::endl;
    return EXTLLVM2::doTheThing(declarations, bitcode(), asmcode, inlineDotLLString());
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
        std::cout << "it seems like this is happening???" << std::endl;
        printf("%p\n", (void *)func);
        return Scheme->F;
    }
    void* fptr = (void *)const_cast<extemp::EXTLLVM2::Fn*>(func);
    return mk_cptr(Scheme, fptr);
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
    const std::string fname(string_value(pair_car(Args)));
    return EXTLLVM2::getFunctionVarargsByName(fname) ? Scheme->T : Scheme->F;
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
    auto func_ptr = (extemp::EXTLLVM2::Fn *)cptr_value(pair_car(Args));
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
        case EXTLLVM2::ArgType::NOTHING:
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

pointer get_named_type(scheme* Scheme, pointer Args)
{
    const char* name = string_value(pair_car(Args));
    if (name[0] == '%') {
        ++name;
    }

    const std::string name2(name);
    const std::string res(EXTLLVM2::getNamedType(name2));
    if (res == "") {
        return Scheme->NIL;
    } else {
        return mk_string(Scheme, res.c_str());
    }
}

pointer export_llvmmodule_bitcode(scheme* Scheme, pointer Args)
{
    void* module(cptr_value(pair_car(Args)));
    const std::string filename(string_value(pair_cadr(Args)));
    if (EXTLLVM2::exportLLVMModuleBitcode(module, filename)) {
        return Scheme->T;
    }
    return Scheme->F;
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
