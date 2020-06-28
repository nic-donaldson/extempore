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
#pragma once

#include "Scheme.h"
#include "BranchPrediction.h"

#include <EXTZONES.h>
#include <EXTLLVM2.h>

struct _llvm_callback_struct_ {
    void (*fptr)(void*, llvm_zone_t*);
    void* dat;
    llvm_zone_t* zone;
};



extern "C"
{
    void llvm_destroy_zone_after_delay(llvm_zone_t* zone, uint64_t delay);

    pointer llvm_scheme_env_set(scheme* _sc, char* sym);
    bool llvm_check_valid_dot_symbol(scheme* sc, char* symbol);
    bool regex_split(char* str, char** a, char** b);

    inline uint64_t string_hash(const char* str);

    EXPORT double imp_randd();
    EXPORT int64_t imp_rand1_i64(int64_t a);
}

// this added for dodgy continuations support

namespace extemp {
namespace EXTLLVM {



void initLLVM();

EXPORT const char* llvm_disassemble(const unsigned char*  Code, int Syntax);

}

}
