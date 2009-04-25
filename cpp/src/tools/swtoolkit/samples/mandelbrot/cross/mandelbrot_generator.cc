// Copyright 2009, Google Inc.
// All rights reserved.
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

#include "cross/mandelbrot_generator.h"
#include <complex>
#include "cross/color_bytes.h"

double MandelbrotGenerator::Sample(double x, double y) const {
  std::complex<double> c(x, y);
  std::complex<double> z;

  for (int i = 0; i < max_iterations_; ++i) {
    z = z * z + c;
    if (abs(z) > 2.0) {
      // Do a few more iterations for smoothing.
      z = z * z + c;
      z = z * z + c;
      // Return smoothened value.
      double len = std::abs(z);
      return i + 1 - std::log(std::log(len))/std::log(2.0);
    }
  }

  // Return -1.0 for points in the set.
  return -1.0;
}

void MandelbrotGenerator::RainbowMap(double val, unsigned char dst[3]) {
  // Clip val to a positive value, since fmod is goofy with negatives.
  // Then use fmod to limit to the range [0, 6)
  if (val < 0.0) {
    val = 6.0 - std::fmod(-val, 6.0);
  } else {
    val = std::fmod(val, 6.0);
  }

  // Find out which hue bucket.
  int hue_bucket = static_cast<int>(val);
  // Find the brightness level of the element that's changing.
  unsigned char a = static_cast<unsigned char>((val - hue_bucket) * 255);
  unsigned char b = 255 - a;

  // Color by hue bucket.
  switch (hue_bucket) {
    case 0:
      dst[kRedByte] = 255;
      dst[kGreenByte] = a;
      dst[kBlueByte] = 0;
      break;

    case 1:
      dst[kRedByte] = b;
      dst[kGreenByte] = 255;
      dst[kBlueByte] = 0;
      break;

    case 2:
      dst[kRedByte] = 0;
      dst[kGreenByte] = 255;
      dst[kBlueByte] = a;
      break;

    case 3:
      dst[kRedByte] = 0;
      dst[kGreenByte] = b;
      dst[kBlueByte] = 255;
      break;

    case 4:
      dst[kRedByte] = a;
      dst[kGreenByte] = 0;
      dst[kBlueByte] = 255;
      break;

    default:  // 5
      dst[kRedByte] = 255;
      dst[kGreenByte] = 0;
      dst[kBlueByte] = b;
      break;
  }
  // 100% solid.
  dst[kAlphaByte] = 255;
}

void MandelbrotGenerator::Render(int width, int height,
                                 unsigned char *dst) const {
  for (int j = 0; j < height; ++j) {
    double jj = (static_cast<double>(j) / height - 0.5) *
        focus_height_ + focus_y_;
    for (int i = 0 ; i < width ; ++i) {
      double ii = (static_cast<double>(i) / width - 0.5) *
          focus_width_ + focus_x_;

      double val = Sample(ii, jj);
      if (val < 0.0) {
        // Set to black for points in the set.
        dst[kRedByte] = 0;
        dst[kGreenByte] = 0;
        dst[kBlueByte] = 0;
        dst[kAlphaByte] = 255;
      } else {
        // Use the rainbow map with an arbitrary scaling factor to color
        // points outside the set.
        RainbowMap(val / 5.0, dst);
      }

      // Advance to the next pixel.
      dst += 4;
    }
  }
}

void MandelbrotGenerator::DemoFocus() {
  set_focus_position(0.001643721971153, 0.822467633298876);
  set_focus_scale(0.0000001, 0.0000001);
}
