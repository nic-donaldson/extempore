#include <EXTLLVMGlobalMap.h>
#include <LLVMIRCompilation.h>

#include <iostream>

int main(int argc, char **argv) {
    if (extemp::EXTLLVM::haveGlobalValue("hello")) {
        return 1;
    }

    {
        std::unordered_set<std::string> expected_syms{"hello", "$123", "____quux"};
        std::unordered_set<std::string> syms;
        extemp::LLVMIRCompilation::insertMatchingSymbols(" @hello @42 @$123 @____quux", extemp::LLVMIRCompilation::globalSymRegex, syms);
        if (expected_syms != syms) {
            std::cerr << "syms contains:" << std::endl;
            for (const auto& sym : syms) {
                std::cerr << sym << ", ";
            }
            std::cerr << std::endl;
            return 1;
        }
    }

    {
        extemp::LLVMIRCompilation IRCompiler;
        // test necessaryGlobalDeclarations
        // the idea of this function is that we need to declare the functions
        // we're linking against as being defined somewhere, except the ones that
        // are defined in the code we're compiling now! so we pass in the code we're
        // going to compile. but also later we prepend more code to the code we want
        // to compile so we pass in the symbols from that prepended code so we
        // don't declare those either
        const std::string mod1 = R"(
define i32 @addone(i32 %x) {
  %x1 = add i32 %x, %x
  ret i32 %x1
})";
        const std::unordered_set<std::string> inlineSyms{"addzero"};
        const std::string mod1Declarations = IRCompiler.necessaryGlobalDeclarations(mod1, inlineSyms);
        if (mod1Declarations != "") {
            std::cerr << "Expected \"\", got \"" << mod1Declarations << "\"" << std::endl;
            return 1;
        }

        // this module is missing
        // declare i32 @addzero(i32), and
        // declare i32 @addone(i32)
        // which it needs to compile.
        // we're going to assume addzero will be prepended so it's going
        // to go in the "sInlineSyms" argument.
        const std::string mod2 = R"(
define i32 @addtwo(i32 %x) {
  %x1 = call i32 @addzero(%x)
  %x2 = call i32 @addone(%x1)
  %x3 = call i32 @addone(%x2)
  ret i32 %x2
})";

        const std::string necessaryDeclaration = "declare i32 @addone(i32)";
        const std::string mod2Declarations = IRCompiler.necessaryGlobalDeclarations(mod2, inlineSyms);
        if (mod2Declarations != necessaryDeclaration) {
            std::cerr << "Expected \"" << necessaryDeclaration << "\", got \"" << mod2Declarations << "\"" << std::endl;
            return 1;
        }
    }

    return 0;
}
