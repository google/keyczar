// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// http://code.google.com/p/protobuf/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This source code was copied from Protobuf and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <keyczar/base/logging.h>

#include <stdio.h>
#include <errno.h>

#include <keyczar/base/string_util.h>

namespace internal {

void DefaultLogHandler(LogLevel level, const char* filename, int line,
                       const std::string& message) {
  static const char* level_names[] = { "INFO", "WARNING", "ERROR", "FATAL" };

  // We use fprintf() instead of cerr because we want this to work at static
  // initialization time.
  if (level == LOGLEVEL_INFO) {
    fprintf(stdout, "[Keyczar] %s\n", message.c_str());
    fflush(stdout);  // Needed on MSVC.
  } else {
    fprintf(stderr, "[Keyczar %s %s:%d] %s\n",
            level_names[level], filename, line, message.c_str());
    fflush(stderr);  // Needed on MSVC.
  }
}

void NullLogHandler(LogLevel level, const char* filename, int line,
                    const std::string& message) {
  // Nothing.
}

static LogHandler* log_handler_ = &DefaultLogHandler;

static std::string SimpleCtoa(char c) { return std::string(1, c); }

#undef DECLARE_STREAM_OPERATOR
#define DECLARE_STREAM_OPERATOR(TYPE, TOSTRING)                     \
  LogMessage& LogMessage::operator<<(TYPE value) {                  \
    message_ += TOSTRING(value);                                    \
    return *this;                                                   \
  }

DECLARE_STREAM_OPERATOR(const std::string&, )
DECLARE_STREAM_OPERATOR(const char*  , )
DECLARE_STREAM_OPERATOR(char         , SimpleCtoa)
DECLARE_STREAM_OPERATOR(int          , IntToString)
DECLARE_STREAM_OPERATOR(uint32         , UintToString)
#undef DECLARE_STREAM_OPERATOR

LogMessage::LogMessage(LogLevel level, const char* filename, int line)
  : level_(level), filename_(filename), line_(line) {}
LogMessage::~LogMessage() {}

void LogMessage::Finish() {
  internal::log_handler_(level_, filename_, line_, message_);
  if (level_ == LOGLEVEL_FATAL) {
    abort();
  }
}

void LogFinisher::operator=(LogMessage& other) {
  other.Finish();
}

}  // namespace internal

LogHandler* SetLogHandler(LogHandler* new_func) {
  LogHandler* old = internal::log_handler_;
  if (old == &internal::NullLogHandler) {
    old = NULL;
  }
  if (new_func == NULL) {
    internal::log_handler_ = &internal::NullLogHandler;
  } else {
    internal::log_handler_ = new_func;
  }
  return old;
}
