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

///////////////////
// LLVM includes //
///////////////////

// must be included before anything which pulls in <Windows.h>
#include "llvm/AsmParser/Parser.h"
#include "llvm/Config/llvm-config.h" // for LLVM_VERSION_STRING

// if you remove this it segfaults for some reason?
// if you look at the header it does some kind of magic so
// maybe that's not unexpected
#include "llvm/ExecutionEngine/MCJIT.h"

#include <random>
#include "stdarg.h"

#include <EXTLLVM.h>
#include <EXTClosureAddressTable.h>
#include <EXTLLVM2.h>
#include <EXTThread.h>
#include <UNIV.h>
#include <TaskScheduler.h>
#include <Scheme.h>
#include <OSC.h>
#include <BranchPrediction.h>
#include <EXTLLVMGlobalMap.h>
#include "math.h"

#ifdef _WIN32
#include <malloc.h>
#else
#include <sys/types.h>
#endif

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifdef _WIN32
#include <experimental/buffer>
#include <experimental/executor>
#include <experimental/internet>
#include <experimental/io_context>
#include <experimental/net>
#include <experimental/netfwd>
#include <experimental/socket>
#include <experimental/timer>
#else
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>         /* host to IP resolution       */
#include <sys/fcntl.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <chrono>
#include <thread>
#else
#include <unistd.h>
#endif

#include "SchemeProcess.h"


EXPORT void* malloc16(size_t Size)
{
#ifdef _WIN32
    return _aligned_malloc(Size, 16);
#else
    void* result;
    if (posix_memalign(&result, 16, Size)) {
        return nullptr;
    }
    return result;
#endif
}

EXPORT void free16(void* Ptr) {
#ifdef _WIN32
    _aligned_free(Ptr);
#else
    free(Ptr);
#endif
}

EXPORT void llvm_runtime_error(int error, void* arg)
{
  ascii_error();
  switch(error){
  case 1:
    printf("LLVM zptr_copy - invalid zptr! %p\n",arg);
    break;
  default:
    break;
  }
  ascii_normal();
  return;
}

EXPORT void llvm_schedule_callback(long long time, void* dat)
{
  // printf("scheduled callback %lld\n",time);
  // extemp::SchemeProcess::I()->extemporeCallback(time,dat);
  extemp::SchemeProcess* proc = extemp::SchemeProcess::I();

  uint64_t current_time = time; //task->getStartTime();
  uint64_t duration = 1000000000; //task->getDuration();
  extemp::TaskScheduler::I()->addTask(current_time, duration, proc->getExtemporeCallback(), dat, 0, true);
  return;
}

EXPORT void* llvm_get_function_ptr(char* fname)
{
  return reinterpret_cast<void*>(extemp::EXTLLVM2::getFunctionAddress(fname));
}

EXPORT char* extitoa(int64_t val)
{
    static THREAD_LOCAL char buf[32];
    sprintf(buf, "%" PRId64, val);
    return buf;
}

EXPORT void llvm_send_udp(char* host, int port, void* message, int message_length)
{
  int length = message_length;

#ifdef _WIN32 // TODO: This should use WinSock on Windows
  std::experimental::net::io_context context;
  // std::experimental::net::ip::udp::resolver::iterator end;
  std::experimental::net::ip::udp::resolver resolver(context);
  std::stringstream ss;
  ss << port;
  std::experimental::net::ip::udp::resolver::results_type res = resolver.resolve(std::experimental::net::ip::udp::v4(), host, ss.str());
  auto iter = res.begin();
  auto end = res.end();
  std::experimental::net::ip::udp::endpoint sa = *iter;

#else
  struct sockaddr_in sa;
  struct hostent* hen; /* host-to-IP translation */

  /* Address resolution stage */
  hen = gethostbyname(host);
  if (!hen) {
    printf("OSC Error: Could no resolve host name\n");
    return;
  }

  memset(&sa, 0, sizeof(sa));

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  memcpy(&sa.sin_addr.s_addr, hen->h_addr_list[0], hen->h_length);
#endif


#ifdef _WIN32
  std::experimental::net::ip::udp::socket* fd = 0;
#else
  int fd = 0;
#endif

#ifdef _WIN32
  int err = 0;
  std::experimental::net::io_context service;
  std::experimental::net::ip::udp::socket socket(service);
  socket.open(std::experimental::net::ip::udp::v4());
  socket.send_to(std::experimental::net::buffer(message, length), sa);
#else
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  //////// Dr Offig addition ////////
  int broadcastEnable = 1;
  int ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
  if (ret) { printf("Error: Could not open set socket to broadcast mode\n"); }
  //////////////////////////////////////
    
  int err = sendto(fd, message, length, 0, (struct sockaddr*)&sa, sizeof(sa));
  close(fd);
#endif
  if(err < 0)
    {
      if(err == EMSGSIZE) {
        printf("Error: OSC message too large: UDP 8k message MAX\n");
      }else{
        printf("Error: Problem sending OSC message %d\n",err);
      }

    }

  return;
}

/////////////////////////////////////////////////
// This added for dodgy continuations support
// ucontext_t* llvm_make_ucontext()
// {
//   ucontext_t* ctx = (ucontext_t*) malloc(sizeof(ucontext_t));
//   ctx->uc_stack.ss_sp   = (void*) malloc(1024*1024); //iterator_stack;
//   ctx->uc_stack.ss_size = 1024*1024;
//   return ctx;
// }

// ucontext_t* llvm_scheme_process_ucontext()
// {
//   extemp::SchemeProcess* proc = extemp::SchemeProcess::I(); //extemp::SchemeProcess::I()->extemporeCallback(time,dat);
//   ucontext_t* ctx = proc->getContext();
//   return ctx;
// }
///////////////////////////////////////////////////

// these are helpers for runtime debugging in llvm
EXPORT void llvm_print_pointer(void* ptr)
{
    printf("llvm:ptr:>%p -- %" PRId64 "\n",ptr,*((int64_t*)ptr));
    return;
}

EXPORT void llvm_print_i32(int32_t num)
{
    printf("llvm:i32:>%d\n",num);
    return;
}

EXPORT void llvm_print_i64(int64_t num)
{
    printf("llvm:i64:>%" PRId64 "\n",num);
    return;
}

EXPORT void llvm_print_f32(float num)
{
    printf("llvm:f32:>%f\n",num);
    return;
}

EXPORT void llvm_print_f64(double num)
{
    printf("llvm:f64:>%f\n",num);
    return;
}

// these shouldn't ever be large, so it should be ok to cast to signed
// int for returning into xtlang (which prefers signed ints). I hope
// this doesn't come back to bite me one day.
static THREAD_LOCAL std::minstd_rand* sRandGen;

EXPORT double imp_randd()
{
    if (unlikely(!sRandGen)) {
        sRandGen = new std::minstd_rand(time(nullptr));
    }
    // The existing implementation *COULD* (p = 1 / RAND_MAX) return 1!, but I don't think that was intended
    return std::uniform_real_distribution<double>()(*sRandGen);
}

EXPORT float imp_randf()
{
    return imp_randd();
}

EXPORT int64_t imp_rand1_i64(int64_t Limit)
{
    return imp_randd() * Limit;
}

EXPORT int64_t imp_rand2_i64(int64_t Start, int64_t Limit)
{
    return imp_randd() * (Limit - Start) + Start;
}

EXPORT int32_t imp_rand1_i32(int32_t Limit)
{
    return imp_randd() * Limit;
}

EXPORT int32_t imp_rand2_i32(int32_t Start, int32_t Limit)
{
    return imp_randd() * (Limit - Start) + Start;
}

EXPORT double imp_rand1_d(double Limit)
{
    return imp_randd() * Limit;
}

EXPORT double imp_rand2_d(double Start, double Limit)
{
    return imp_randd() * (Limit - Start) + Start;
}

EXPORT float imp_rand1_f(float Limit)
{
    return imp_randf() * Limit;
}

EXPORT float imp_rand2_f(float Start, float Limit)
{
    return imp_randf() * (Limit - Start) + Start;
}






EXPORT extemp::ClosureAddressTable::closure_address_table* add_address_table(llvm_zone_t* zone, char* name, uint32_t offset, char* type, int alloctype, struct extemp::ClosureAddressTable::closure_address_table* table)
{
    struct extemp::ClosureAddressTable::closure_address_table* t = NULL;
    if (alloctype == 1) {
        t = reinterpret_cast<extemp::ClosureAddressTable::closure_address_table*>(malloc(sizeof(struct extemp::ClosureAddressTable::closure_address_table)));
    } else {
        t = (struct extemp::ClosureAddressTable::closure_address_table*) extemp::EXTZONES::llvm_zone_malloc(zone,sizeof(struct extemp::ClosureAddressTable::closure_address_table));
    }
    t->id = string_hash(name);
    t->name = name;
    t->offset = offset;
    t->type = type;
    t->next = table;
    return t;
}

bool llvm_check_valid_dot_symbol(scheme* sc, char* symbol) {
  char c[1024];
  auto pos(strchr(symbol, '.'));
  if (!pos) {
    //printf("Eval error: not valid dot syntax\n");
    return false;
  }
  strncpy(c, symbol, pos - symbol);
  c[pos - symbol] = '\0';
  pointer x = find_slot_in_env(sc, sc->envir, mk_symbol(sc, c), 1);
  if (x == sc->NIL) {
    return false;
  }
  strcat(c, "_xtlang_name");
  pointer y = find_slot_in_env(sc, sc->envir, mk_symbol(sc, c), 1);
  return y != sc->NIL;
}

uint64_t string_hash(const char* str)
{
    uint64_t result(0);
    unsigned char c;
    while((c = *(str++))) {
        result = result * 33 + uint8_t(c);
    }
    return result;
}

static char* get_address_type(uint64_t id, extemp::ClosureAddressTable::closure_address_table* table)
{
    while (table)
    {
        if (table->id == id) {
            return table->type;
        }
        table = table->next;
    }
    printf("Unable to locate id in closure environment c\n");
    return nullptr;
}

pointer llvm_scheme_env_set(scheme* _sc, char* sym)
{
  using namespace llvm;
  char fname[256];
  char tmp[256];
  char vname[256];
  char tname[256];

  char c[1024];
  c[0] = '\0';
  const char* d = "_xtlang_name";

  if(!(rsplit((char*)"\\.",sym, (char*) fname, (char*) tmp))) {
    printf("Error attempting to set environment variable in closure bad split %s\n",sym);
    return _sc->F;
  }
  if(!rsplit((char*)":",tmp, (char*) vname,(char*) tname)) {
    tname[0] = '\0';
    std::memcpy(vname, tmp, 256);
  }
  strcat(c,fname);
  strcat(c,d);
  pointer xtlang_f_name = find_slot_in_env(_sc,_sc->envir,mk_symbol(_sc,c),1);
  char* xtlang_name = strvalue(pair_cdr(xtlang_f_name));
  //printf("in llvm scheme env set %s.%s:%s  xtlang:%s\n",fname,vname,tname,xtlang_name);
  uint64_t id = string_hash(vname);
  // Module* M = extemp::EXTLLVM::M;
  std::string funcname(xtlang_name);
  std::string getter("_getter");
  void*(*p)() = (void*(*)()) extemp::EXTLLVM2::getFunctionAddress(funcname + getter);
  if (!p) {
    printf("Error attempting to set environment variable in closure %s.%s\n",fname,vname);
    return _sc->F;
  }

  size_t*** closur = (size_t***) p();
  size_t** closure = *closur;
  //uint32_t** closure = (uint32_t**) cptr_value(pair_car(args));
  extemp::ClosureAddressTable::closure_address_table* addy_table = (extemp::ClosureAddressTable::closure_address_table*) *(closure+0);
  // check address exists
  if(!check_address_exists(id, addy_table)) {
    ascii_error();
    printf("RunTime Error:");
    ascii_normal();
    printf(" slot");
    ascii_warning();
    printf(" %s.%s ",fname,vname);
    ascii_normal();
    printf("does not exist!\n");
    ascii_default();
    return _sc->F;
  }
  char* eptr = (char*) *(closure+1);
  char* type = get_address_type(id,addy_table);
  uint32_t offset = extemp::ClosureAddressTable::get_address_offset(id,addy_table);

  //printf("type: %s  offset: %d\n",type, offset);

  pointer value = 0;
  if(_sc->args == _sc->NIL) {
    //value = 0;
    value = _sc->NIL;
  } else {
    value = pair_car(_sc->args);
  }

  if(strcmp(type,"i32")==0) {
    int32_t** ptr = (int32_t**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_integer(_sc, **ptr);
    } else {
      **ptr = (int32_t) ivalue(value);
      return _sc->T;
    }
  }else if(strcmp(type,"i64")==0){
    uint64_t** ptr = (uint64_t**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_integer(_sc, **ptr);
    } else {
      **ptr = ivalue(value);
      return _sc->T;
    }
  }else if(strcmp(type,"float") == 0){
    float** ptr = (float**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_real(_sc, **ptr);
    } else {
      **ptr = rvalue(value);
      return _sc->T;
    }
  }else if(strcmp(type,"double")==0){
    double** ptr = (double**) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_real(_sc, **ptr);
    } else {
      **ptr = rvalue(value);
      return _sc->T;
    }
  }else{ // else pointer type
    char*** ptr = (char***) (eptr+offset);
    if(value == _sc->NIL) {
      return mk_cptr(_sc, (void*) **ptr);
    } else {
      **ptr = (char*) cptr_value(value);
      //printf("Unsuported type for closure environment set\n");
      return _sc->T;
    }
  }
  // shouldn't get to here
  return _sc->F;
}


namespace extemp {
namespace EXTLLVM {

// TODO: seems like we could remove the indirection
uintptr_t getSymbolAddress(const std::string& name) {
    return extemp::EXTLLVM2::getSymbolAddress(name);
}

// TODO: seems like we could maybe remove the indirection
EXPORT const char* llvm_disassemble(const unsigned char* Code, int syntax)
{
    return extemp::EXTLLVM2::llvm_disassemble(Code, syntax);
}

static extemp::CMG DestroyMallocZoneWithDelayCM(
        [](extemp::TaskI* Task)->void {
            extemp::EXTZONES::llvm_zone_destroy(static_cast<extemp::Task<llvm_zone_t*>*>(Task)->getArg());
        });

EXPORT void llvm_destroy_zone_after_delay(llvm_zone_t* Zone, uint64_t Delay)
{
    extemp::TaskScheduler::I()->add(new extemp::Task<llvm_zone_t*>(extemp::UNIV::TIME + Delay, extemp::UNIV::SECOND(),
            &DestroyMallocZoneWithDelayCM, Zone));
}

static extemp::CMG FreeWithDelayCM(
        [](extemp::TaskI* Task)->void {
            free(static_cast<extemp::Task<char*>*>(Task)->getArg());
        });

EXPORT void free_after_delay(char* Data, double Delay)
{
    extemp::TaskScheduler::I()->add(new extemp::Task<char*>(extemp::UNIV::TIME + Delay, extemp::UNIV::SECOND(),
            &FreeWithDelayCM, Data));
}





EXPORT void ascii_text_color_extern(int32_t Bold, int32_t Foreground, int32_t Background)
{
    ascii_text_color(Bold, Foreground, Background);
}

// CATEGORY: clock

EXPORT double clock_clock()
{
    return getRealTime() + extemp::UNIV::CLOCK_OFFSET;
}

EXPORT double audio_clock_base()
{
    return extemp::UNIV::AUDIO_CLOCK_BASE;
}

EXPORT double audio_clock_now()
{
    return extemp::UNIV::AUDIO_CLOCK_NOW;
}

// CATEGORY: native mutex

EXPORT void* mutex_create()
{
    auto mutex(new EXTMutex);
    mutex->init();
    return mutex;
}

EXPORT int mutex_destroy(void* Mutex)
{
    delete reinterpret_cast<EXTMutex*>(Mutex);
    return 0;
}

EXPORT int mutex_lock(void* Mutex)
{
    reinterpret_cast<EXTMutex*>(Mutex)->lock();
    return 0;
}

EXPORT int mutex_unlock(void* Mutex)
{
    reinterpret_cast<EXTMutex*>(Mutex)->unlock();
    return 0;
}

EXPORT int mutex_trylock(void* Mutex)
{
    return reinterpret_cast<EXTMutex*>(Mutex)->try_lock();
}

// CATEGORY: native thread

EXPORT void* thread_fork(EXTThread::function_type Start, void* Args) {
    auto thread(new extemp::EXTThread(Start, Args, "xt_fork"));
    thread->start();
    return thread;
}

EXPORT void thread_destroy(void* Thread)
{
    delete reinterpret_cast<EXTThread*>(Thread);
}

EXPORT int thread_join(void* Thread)
{
    return reinterpret_cast<EXTThread*>(Thread)->join();
}

EXPORT int thread_kill(void* Thread)
{
    return reinterpret_cast<EXTThread*>(Thread)->kill();
}

EXPORT int thread_equal(void* Thread1, void* Thread2)
{
    return Thread1 == Thread2;
}

EXPORT int thread_equal_self(void* Thread)
{
    return reinterpret_cast<EXTThread*>(Thread)->isCurrentThread();
}

EXPORT void* thread_self()
{
    return EXTThread::activeThread();
}

EXPORT int64_t thread_sleep(int64_t Secs, int64_t Nanosecs)
{
#ifdef _WIN32
    std::this_thread::sleep_for(std::chrono::seconds(Secs) + std::chrono::nanoseconds(Nanosecs));
    return 0;
#else
    timespec a = { Secs, Nanosecs };
    timespec b;
    while (true) {
        auto res(nanosleep(&a ,&b));
        if (likely(!res)) {
            return 0;
        }
        if (unlikely(errno != EINTR)) {
            return -1;
        }
        a = b;
    }
#endif
}


void initLLVM()
{
    if (!extemp::EXTLLVM2::initLLVM()) {
        return;
    }

    // tell LLVM about some built-in functions
    extemp::EXTLLVM2::addGlobalMapping("llvm_zone_destroy",
                                       uintptr_t(&extemp::EXTZONES::llvm_zone_destroy));
    extemp::EXTLLVM2::addGlobalMapping("get_address_offset",
                                       (uint64_t)&extemp::ClosureAddressTable::get_address_offset);
    extemp::EXTLLVM2::addGlobalMapping("string_hash", (uint64_t)&string_hash);
    extemp::EXTLLVM2::addGlobalMapping("swap64i", (uint64_t)&swap64i);
    extemp::EXTLLVM2::addGlobalMapping("swap64f", (uint64_t)&swap64f);
    extemp::EXTLLVM2::addGlobalMapping("swap32i", (uint64_t)&swap32i);
    extemp::EXTLLVM2::addGlobalMapping("swap32f", (uint64_t)&swap32f);
    extemp::EXTLLVM2::addGlobalMapping("unswap64i", (uint64_t)&unswap64i);
    extemp::EXTLLVM2::addGlobalMapping("unswap64f", (uint64_t)&unswap64f);
    extemp::EXTLLVM2::addGlobalMapping("unswap32i", (uint64_t)&unswap32i);
    extemp::EXTLLVM2::addGlobalMapping("unswap32f", (uint64_t)&unswap32f);
    extemp::EXTLLVM2::addGlobalMapping("rsplit", (uint64_t)&rsplit);
    extemp::EXTLLVM2::addGlobalMapping("rmatch", (uint64_t)&rmatch);
    extemp::EXTLLVM2::addGlobalMapping("rreplace", (uint64_t)&rreplace);
    extemp::EXTLLVM2::addGlobalMapping("r64value", (uint64_t)&r64value);
    extemp::EXTLLVM2::addGlobalMapping("mk_double", (uint64_t)&mk_double);
    extemp::EXTLLVM2::addGlobalMapping("r32value", (uint64_t)&r32value);
    extemp::EXTLLVM2::addGlobalMapping("mk_float", (uint64_t)&mk_float);
    extemp::EXTLLVM2::addGlobalMapping("mk_i64", (uint64_t)&mk_i64);
    extemp::EXTLLVM2::addGlobalMapping("mk_i32", (uint64_t)&mk_i32);
    extemp::EXTLLVM2::addGlobalMapping("mk_i16", (uint64_t)&mk_i16);
    extemp::EXTLLVM2::addGlobalMapping("mk_i8", (uint64_t)&mk_i8);
    extemp::EXTLLVM2::addGlobalMapping("mk_i1", (uint64_t)&mk_i1);
    extemp::EXTLLVM2::addGlobalMapping("string_value", (uint64_t)&string_value);
    extemp::EXTLLVM2::addGlobalMapping("mk_string", (uint64_t)&mk_string);
    extemp::EXTLLVM2::addGlobalMapping("cptr_value", (uint64_t)&cptr_value);
    extemp::EXTLLVM2::addGlobalMapping("mk_cptr", (uint64_t)&mk_cptr);
    extemp::EXTLLVM2::addGlobalMapping("sys_sharedir", (uint64_t)&sys_sharedir);
    extemp::EXTLLVM2::addGlobalMapping("sys_slurp_file",
                                       (uint64_t)&sys_slurp_file);

    // it's a bit awkward that we do it this way but we'll get there...
    extemp::EXTLLVM2::finalize();

    return;
}
}
}

