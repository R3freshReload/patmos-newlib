// Copyright 2012 Technical University of Denmark, DTU Compute
// Author: Florian Brandner
// 
// This file is part of the newlib C library for the Patmos processor.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are met:
//
//      1. Redistributions of source code must retain the above copyright notice,
//         this list of conditions and the following disclaimer.
//
//      2. Redistributions in binary form must reproduce the above copyright
//         notice, this list of conditions and the following disclaimer in the
//         documentation and/or other materials provided with the distribution.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
//   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
//   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
//   NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
//   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
//   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//   The views and conclusions contained in the software and documentation are
//   those of the authors and should not be interpreted as representing official
//   policies, either expressed or implied, of the copyright holder.

#include <errno.h>

#undef errno
extern int  errno;

//******************************************************************************
/// patmos-plug: close: Implements the default `_close` implementation used when
/// no specific implementation is provided at link time.
/// Called if `patmosplug_close(int)` is not defined.
int _patmosplug_close(int file) {
  // TODO: implement for simulator target
  errno = EBADF;
  return -1;
}
/// patmosplug_close: Alternative, patmos-specific `_close` implementation that
/// can be provided at program link time.
/// If not provided, will default to calling `_patmosplug_close`.
int patmosplug_close(int file)
    __attribute__((weak, alias("_patmosplug_close")));

//******************************************************************************
/// _close - close a file descriptor.
int _close(int file)
{
  return patmosplug_close(file);
}
