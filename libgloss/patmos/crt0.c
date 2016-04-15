// Copyright 2012 Florian Brandner
//
// This file is part of the newlib C library for the Patmos processor.
//
// This file is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This code is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// (COPYING3.LIB). If not, see <http://www.gnu.org/licenses/>.

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <reent.h>

#include "patmos.h"

//******************************************************************************
/// start and end of BSS section
extern int __bss_start, _end;

/// top of stack cache and shadow stack
extern int _shadow_stack_base, _stack_cache_base;

//******************************************************************************
typedef void (*funptr_t)(void);

/// init - initializer, used to call static constructors.
extern funptr_t __init_array_begin[0];
extern funptr_t __init_array_end[0];
void __init(void) __attribute__((noinline));

/// fini - finalizer, used to call static destructors.
extern funptr_t __fini_array_begin[0];
extern funptr_t __fini_array_end[0];
void __fini(void) __attribute__((noinline));

//******************************************************************************

/// main - main function.
/// Note: LLVM currently silently ignores attributes for extern functions!
extern int main(int argc, char **argv) __attribute__((noinline));

/// memset - set memory content.
void *memset(void *s, int c, size_t n);

/// atexit - register call backs on program termination.
extern int atexit(void (*function)(void));

/// exit - terminate program.
extern void exit(int status) __attribute__((noinline));

//******************************************************************************
/// __env - values of environment vairables.
char *__env[1] = {0};

/// environ - values of environment vairables.
char **environ = __env;

/// MAX_CORES - the maximum number of cores
#define MAX_CORES 64
/// _loader_baseaddr - the base address of the loading function (one per core)
unsigned _loader_baseaddr[MAX_CORES];
/// _loader_off - the offset of the loading function (one per core)
unsigned _loader_off[MAX_CORES];

/// _reent_ptr - data structure for reentrant library calls
struct _reent *_reent_ptr [MAX_CORES];
/// __initreent - initialize reentrancy structure
void __initreent(void) __attribute__((noinline));


/// __init_exceptions - install default exception handlers
void  __init_exceptions(void);
/// __default_exc_handler - a default exception handler
void __default_exc_handler(void);

// Forward declaration of __start for _start.
void __start();

//******************************************************************************
/// _start - main entry function to all patmos executables.
/// Setup the stack frame and invoke __start.
void _start() __attribute__((naked,used));
void _start()
{
  // ---------------------------------------------------------------------------
  // retrieve the id of the current core
  // store id in $r1
  asm volatile("li $r1 = %0;"
               "lwl $r1 = [$r1];"
               "nop;"
               : : "i" (__PATMOS_CPUINFO_COREID));

  // ---------------------------------------------------------------------------
  // store return information of caller
  asm volatile ("shadd2 $r2 = $r1, %0;"
                "mfs $r3 = $srb;"
                "swm [$r2] = $r3;"
                "shadd2 $r2 = $r1, %1;"
                "mfs $r3 = $sro;"
                "swm [$r2] = $r3;"
                : : "i" (&_loader_baseaddr[0]), "i" (&_loader_off[0]));

  // ---------------------------------------------------------------------------
  // setup stack frame and stack cache.

  // compute stack size, using bit-twiddling to compute absolute size
  // store size in $r4, keep base addresses in $r2 and $r3
  asm volatile ("li $r2 = %0;"
                "li $r3 = %1;"
                "sub $r4 = $r3, $r2;"
                "sra $r5 = $r4, 31;"
                "add $r4 = $r4, $r5;"
                "xor $r4 = $r4, $r5;"
                : : "i" (&_shadow_stack_base), "i" (&_stack_cache_base));

  // compute effective stack addresses (needed for CMPs)
  // store effective addresses in $r2 and $r3
  asm volatile ("mul $r4, $r1;"
                "nop;"
                "mfs $r4 = $s2;"
                "sl $r4 = $r4, 1;"
                "sub $r2 = $r2, $r4;"
                "sub $r3 = $r3, $r4;"
                );

  // ---------------------------------------------------------------------------
  // setup stack frame and stack cache.
  asm volatile ("mov $r31 = $r2;" // initialize shadow stack pointer"
                "mts $ss  = $r3;" // initialize the stack cache's spill pointer"
                "mts $st  = $r3;" // initialize the stack cache's top pointer"
                );

  // ---------------------------------------------------------------------------
  // continue in __start

  // We use asm here to prevent LLVM from messing with the stack.
  // Calling (or actually any kind of more complex C code) is not supported by
  // the compiler, since it does not manage the stack in naked functions. If it 
  // spills registers at -O0, this can lead to stack corruption.
  // It would work in this case since it is a non-returning tail call without
  // arguments, but we should rather be defensive in system code.
  // If LLVM would inline the call, we could get code requiring spills into this
  // function (but the noinline attribute prevents this anyway).
  // If we need to analyse this code, we can easily extend the compiler and
  // platin to support inline asm (and we should, anyway!).
  asm volatile ("li $r1 = %0;"
                "call $r1;"       // resume in the no-return __start function
                "nop  ;"
                "nop  ;"
                "nop  ;"	  // no need for a 'ret'
                 : : "i" (&__start));
}

/// __start - Main driver for program setup and execution.
/// Initialize data structures, invoke main, et cetera.
/// TODO needs a better name to make it more distinguishable from _start.
void __start() __attribute__((noinline));
void __start()
{
  // ---------------------------------------------------------------------------  
  // clear the BSS section
  // memset(&__bss_start, 0, &_end - &__bss_start);

  // ---------------------------------------------------------------------------  
  // initialize reentrancy structure
  __initreent();

  // ---------------------------------------------------------------------------  
  // install basic exception handlers
  __init_exceptions();

  // ---------------------------------------------------------------------------  
  // call initializers
  __init();

  // register callback to fini
  atexit(&__fini);

  // ---------------------------------------------------------------------------  
  // invoke main -- without command line options

  // LLVM does not attach function attributes to declarations, we cannot mark
  // main as noinline in this file. 
  // Thus, we again use inline asm here for the call, but this time to prevent
  // inlining *of main* to avoid breaking evaluation and debugging scripts.
  // We also keep the call to exit while we are at it, to make debugging traces
  // easier.
  asm volatile ("call %0;"        // invoke main function
                "li   $r3 = 0;"   // argc
                "li   $r4 = 0;"   // argv
                "nop  ;"
                "call %1;"        // terminate program and invoke exit
                "mov  $r3 = $r1;" // get exit code (in delay slot)
                "nop  ;"
                "nop  ;"
                : : "r" (&main), "r" (&exit)
                : "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7", "$r8",
                  "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", "$r16",
                  "$r17", "$r18", "$r19", "$r20");

  // ---------------------------------------------------------------------------
  // in case this returns
  while(1) /* do nothing */;
}

/// init - initializer, used to call static constructors.
void __init(void) {
  for (funptr_t *i = __init_array_begin; i < __init_array_end; i++) {
    (*i)();
  }
}

/// fini - finalizer, used to call static destructors.
void __fini(void) {
  for (funptr_t *i = __fini_array_end-1; i >= __fini_array_begin; --i) {
    (*i)();
  }
}

/// __initreent - initialize reentrancy structure
void __initreent(void) {
  const int id = *((_iodev_ptr_t)(__PATMOS_CPUINFO_COREID));
  _reent_ptr[id] = malloc(sizeof(struct _reent));
  _REENT_INIT_PTR(_reent_ptr[id]);
}

/// __getreent - get reentrancy structure for current thread
struct _reent *__getreent(void)
{
  const int id = *((_iodev_ptr_t)(__PATMOS_CPUINFO_COREID));
  return _reent_ptr[id];
}

/// __init_exceptions - install default exception handlers
void  __init_exceptions(void) {
  int i;
  // only install handlers if in privileged mode
  if (*((_iodev_ptr_t)(__PATMOS_EXCUNIT_STATUS)) & 0x2) {
    for (i = 0; i < 32; i++) {
      *((_IODEV exc_handler_t *)(__PATMOS_EXCUNIT_VEC + 4*i)) = &__default_exc_handler;
    }
  }
}

/// __default_exc_handler - a default exception handler
void __default_exc_handler(void) {
  unsigned source = *((_iodev_ptr_t)(__PATMOS_EXCUNIT_SRC));

  unsigned base, off;
  asm volatile("mfs %0 = $sxb;"
               "mfs %1 = $sxo;"
               : "=r" (base), "=r" (off));

  const char *msg = "";
  switch(source) {
  case 0: msg = " (illegal operation)"; break;
  case 1: msg = " (illegal memory access)"; break;
  }

  printf("Aborting: exception %d%s at %#010x\n", source, msg, base+off);

  abort();
}
