// Copyright 2009 Sebastien Martini (seb@dbzteam.org)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <keyczar/base/zlib.h>

#include <zlib.h>

#include <keyczar/base/logging.h>
#include <keyczar/base/stl_util-inl.h>

namespace {

static const int kBufferSize = 65536;

}  // namespace

namespace keyczar {
namespace base {

// static
bool Zlib::Compress(Format format, const std::string& input,
                    std::string* output) {
  if (output == NULL)
    return false;

  z_stream zcontext;
  int zerror = 0;

  // allocate deflate state
  zcontext.zalloc = Z_NULL;
  zcontext.zfree = Z_NULL;
  zcontext.opaque = Z_NULL;

  // Target format
  // Use GZIP format by default
  int window_bits_format = 16;
  if (format == ZLIB)
    window_bits_format = 0;

  zerror = deflateInit2(
      &zcontext,
      Z_BEST_COMPRESSION,
      Z_DEFLATED,
      /* windowBits */15 | window_bits_format,
      /* memLevel (default) */8,
      Z_DEFAULT_STRATEGY);
  if (zerror != Z_OK)
    return false;

  zcontext.avail_in = input.size();
  zcontext.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));

  int output_pos = output->size();
  do {
    base::STLStringResizeUninitialized(output, output_pos + kBufferSize);
    zcontext.next_out = reinterpret_cast<Bytef*>(
        base::string_as_array(output) + output_pos);
    zcontext.avail_out = kBufferSize;

    zerror = deflate(&zcontext, Z_FINISH);
    if (zerror != Z_OK && zerror != Z_STREAM_END)
      return false;

    output_pos += kBufferSize - zcontext.avail_out;
  } while (zcontext.avail_out == 0);

  CHECK_EQ(zcontext.avail_in, 0);
  CHECK_EQ(zerror, Z_STREAM_END);

  deflateEnd(&zcontext);
  output->resize(output_pos);
  return true;
}

// static
bool Zlib::Decompress(Format format, const std::string& input,
                      std::string* output) {
  if (output == NULL)
    return false;

  z_stream zcontext;
  int zerror = 0;

  // allocate deflate state
  zcontext.zalloc = Z_NULL;
  zcontext.zfree = Z_NULL;
  zcontext.opaque = Z_NULL;

  // Target format
  int window_bits_format = 0;
  switch (format) {
    case AUTO:
      window_bits_format = 32;
      break;
    case GZIP:
      window_bits_format = 16;
      break;
    case ZLIB:
      window_bits_format = 0;
      break;
  }

  zerror = inflateInit2(
      &zcontext,
      /* windowBits */15 | window_bits_format);
  if (zerror != Z_OK)
    return false;

  zcontext.avail_in = input.size();
  zcontext.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));

  int output_pos = output->size();
  do {
    base::STLStringResizeUninitialized(output, output_pos + kBufferSize);
    zcontext.next_out = reinterpret_cast<Bytef*>(
        base::string_as_array(output) + output_pos);
    zcontext.avail_out = kBufferSize;

    zerror = inflate(&zcontext, Z_FINISH);
    if (zerror != Z_OK && zerror != Z_STREAM_END)
      return false;

    output_pos += kBufferSize - zcontext.avail_out;
  } while (zcontext.avail_out == 0);

  CHECK_EQ(zcontext.avail_in, 0);
  CHECK_EQ(zerror, Z_STREAM_END);

  inflateEnd(&zcontext);
  output->resize(output_pos);
  return true;
}

}  // namespace base
}  // namespace keyczar
