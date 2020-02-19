#pragma once
struct cell;
typedef struct cell* pointer;
typedef struct scheme scheme;

namespace extemp {
namespace SchemeFFI {
namespace LLVM {
  pointer optimizeCompiles(scheme* Scheme, pointer Args);
  pointer jitCompileIRString(scheme *Scheme, pointer Args);
  pointer get_function(scheme* Scheme, pointer Args);
  pointer get_globalvar(scheme* Scheme, pointer Args);
  pointer get_struct_size(scheme* Scheme, pointer Args);
  pointer get_named_struct_size(scheme* Scheme, pointer Args);
  pointer get_function_args(scheme* Scheme, pointer Args);
  pointer get_function_varargs(scheme* Scheme, pointer Args);
  pointer get_function_type(scheme* Scheme, pointer Args);
  pointer get_function_calling_conv(scheme* Scheme, pointer Args);
  pointer get_global_variable_type(scheme* Scheme, pointer Args);
  pointer get_function_pointer(scheme* Scheme, pointer Args);
  pointer remove_function(scheme* Scheme, pointer Args);
  pointer remove_global_var(scheme* Scheme, pointer Args);
  pointer erase_function(scheme* Scheme, pointer Args);
  pointer llvm_call_void_native(scheme* Scheme, pointer Args);
  pointer call_compiled(scheme* Scheme, pointer Args);
  pointer llvm_convert_float_constant(scheme* Scheme, pointer Args);
  pointer llvm_convert_double_constant(scheme* Scheme, pointer Args);
  pointer llvm_count(scheme* Scheme, pointer Args);
  pointer llvm_count_inc(scheme* Scheme, pointer Args);
  pointer llvm_count_set(scheme* Scheme, pointer Args);
  pointer callClosure(scheme* Scheme, pointer Args);
  pointer llvm_print_all_modules(scheme* Scheme, pointer Args);
  pointer printLLVMFunction(scheme* Scheme, pointer Args);
  pointer llvm_print_all_closures(scheme* Scheme, pointer Args);
  pointer llvm_print_closure(scheme* Scheme, pointer Args);
  pointer llvm_closure_last_name(scheme* Scheme, pointer Args);
  pointer bind_symbol(scheme* Scheme, pointer Args);
  pointer update_mapping(scheme* Scheme, pointer Args);
  pointer get_named_type(scheme* Scheme, pointer Args);
  pointer export_llvmmodule_bitcode(scheme* Scheme, pointer Args);
}
} // namespace SchemeFFI
} // namespace extemp
