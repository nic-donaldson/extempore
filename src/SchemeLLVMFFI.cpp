#include <SchemeLLVMFFI.h>

#include <Scheme.h>
#include <SchemePrivate.h>
#include <EXTLLVM2.h>
#include <EXTLLVM.h>

namespace extemp {
namespace SchemeFFI {
namespace LLVM {
    pointer optimizeCompiles(scheme* Scheme, pointer Args)
    {
        EXTLLVM2::OPTIMIZE_COMPILES = (pair_car(Args) == Scheme->T);
        return Scheme->T;
    }
} // namespace LLVM
} // namespace SchemeFFI
} // namespace extemp
