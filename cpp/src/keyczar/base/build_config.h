// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file adds defines about the platform we're currently building on.
//  Operating System:
//    OS_WIN / OS_MACOSX / OS_LINUX / OS_BSD / OS_POSIX (MACOSX or LINUX or BSD)
//  Compiler:
//    COMPILER_MSVC / COMPILER_GCC
//  Processor:
//    ARCH_CPU_X86 / ARCH_CPU_X86_64 / ARCH_CPU_X86_FAMILY (X86 or X86_64)
//    ARCH_CPU_32_BITS / ARCH_CPU_64_BITS / ARCH_CPU_ARMEL

#ifndef KEYCZAR_BASE_BUILD_CONFIG_H_
#define KEYCZAR_BASE_BUILD_CONFIG_H_

// A set of macros to use for platform detection.
#if defined(__APPLE__)
#ifndef OS_MACOSX
#define OS_MACOSX 1
#endif
#elif defined(__linux__)
#ifndef OS_LINUX
#define OS_LINUX 1
#endif
#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__)
#ifndef OS_BSD
#define OS_BSD 1
#endif
#elif defined(_WIN32)
#ifndef OS_WIN
#define OS_WIN 1
#endif
#else
#error Please add support for your platform in keyczar/base/build_config.h
#endif

// For access to standard POSIX features, use OS_POSIX instead of a more
// specific macro.
#if defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_BSD)
#define OS_POSIX 1
#endif

// Compiler detection.
#if defined(__GNUC__)
#define COMPILER_GCC 1
#elif defined(_MSC_VER)
#define COMPILER_MSVC 1
#else
#error Please add support for your compiler in keyczar/base/build_config.h
#endif

// Processor architecture detection.  For more info on what's defined, see:
//   http://msdn.microsoft.com/en-us/library/b0084kay.aspx
//   http://www.agner.org/optimize/calling_conventions.pdf
//   or with gcc, run: "echo | gcc -E -dM -"
#if defined(_M_X64) || defined(__x86_64__)
#define ARCH_CPU_X86_FAMILY 1
#define ARCH_CPU_X86_64 1
#define ARCH_CPU_64_BITS 1
#elif defined(_M_IX86) || defined(__i386__)
#define ARCH_CPU_X86_FAMILY 1
#define ARCH_CPU_X86 1
#define ARCH_CPU_32_BITS 1
#elif defined(__ARMEL__)
#define ARCH_CPU_ARM_FAMILY 1
#define ARCH_CPU_ARMEL 1
#define ARCH_CPU_32_BITS 1
#else
#error Please add support for your architecture in keyczar/base/build_config.h
#endif

#endif  // KEYCZAR_BASE_BUILD_CONFIG_H_
