#pragma once
struct cell;
typedef struct cell* pointer;
typedef struct scheme scheme;

namespace extemp {
namespace SchemeFFI {
namespace LLVM {
  pointer optimizeCompiles(scheme* Scheme, pointer Args);
}
} // namespace SchemeFFI
} // namespace extemp
