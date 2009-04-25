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

#ifndef CROSS_MANDELBROT_GENERATOR_H_
#define CROSS_MANDELBROT_GENERATOR_H_

#include "cross/image_generator_interface.h"

// An image generator for the Mandelbrot Set.
class MandelbrotGenerator : public ImageGeneratorInterface {
 public:
  // Create a new Mandelbrot Set generator.
  // By default focus on the origin with a view of 4 x 4.
  // Pick a reasonable limit on the number of iterations.
  MandelbrotGenerator() {
    focus_x_ = 0.0;
    focus_y_ = 0.0;
    focus_width_ = 4.0;
    focus_height_ = 4.0;
    max_iterations_ = 200;
  }

  // Set the focus position.
  void set_focus_position(double x, double y) {
    focus_x_ = x;
    focus_y_ = y;
  }

  // Set the scale.
  void set_focus_scale(double width, double height) {
    focus_width_ = width;
    focus_height_ = height;
  }

  // Set the maximum number of iterations.
  void set_max_iterations(int max_iterations) {
    max_iterations_ = max_iterations;
  }

  // Focus on an interesting part of the set as a demo.
  void DemoFocus();

  // Render a view.
  virtual void Render(int width, int height,
                      unsigned char *target_image) const;

 private:
  // Sample the Mandelbrot Set at a particular x,y coordinate.
  // Returns -1.0 for values in the set.
  // Returns >=0.0 value with smooth gradients outside the set.
  double Sample(double x, double y) const;

  // Convert a value to an RGBA pixel value.
  // The color moves smoothly in a rainbow colored loop.
  static void RainbowMap(double val, unsigned char dst[3]);

  // Keep the focus location and scale.
  double focus_x_, focus_y_;
  double focus_width_, focus_height_;
  // Keep the number of iterations to use in image generation.
  int max_iterations_;
};

#endif  // CROSS_MANDELBROT_GENERATOR_H_
