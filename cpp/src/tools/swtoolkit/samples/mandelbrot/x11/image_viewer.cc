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

#include "x11/image_viewer.h"
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdlib.h>
#include "cross/mandelbrot_generator.h"

void ImageViewer::View(const char *title,
                       const ImageGeneratorInterface& source) {
  // Open main display.
  Display *display = XOpenDisplay(NULL);
  // Get default screen.
  int screen = XDefaultScreen(display);
  // Get root window.
  Window root_window = XRootWindow(display, screen);
  // Get default visual.
  Visual *visual = XDefaultVisual(display, screen);
  // Get default depth
  int depth = XDefaultDepth(display, screen);
  // Get black and white.
  // NOTE: these fail cpplint but are the right type to use with X11.
  unsigned long black = XBlackPixel(display, screen);
  unsigned long white = XWhitePixel(display, screen);
  // Create a window.
  Window window = XCreateSimpleWindow(display, root_window,
                                      100, 100, 500, 400,
                                      4, black, white);
  // Set window title.
  XStoreName(display, window, title);
  // Select certain types of input.
  XSelectInput(display, window,
               ExposureMask | StructureNotifyMask |
               KeyPressMask | ButtonPressMask);
  // Create a graphics context.
  GC gc = XCreateGC(display, window, 0, 0);
  // Actually show the window.
  XMapWindow(display, window);

  // Event handler loop.
  bool done = false;
  int width = 1;
  int height = 1;
  while (!done) {
    XEvent event;
    XNextEvent(display, &event);
    switch (event.type) {
      // Quit if a key of button is pressed.
      case KeyPress:
      case ButtonPress:
        done = true;
        break;

      case ConfigureNotify:
        // Store window size.
        width = event.xconfigure.width;
        height = event.xconfigure.height;
        break;

      case Expose:
        // Skip this if it's not the last expose event in the buffer.
        if (event.xexpose.count) break;
        // Create buffer for image.
        // NOTE: XDestroyImage will handle freeing this.
        unsigned char *pix = (unsigned char*)malloc(width * height * 4);
        // Generate image.
        source.Render(width, height, pix);

        // Draw it.
        XImage *image = XCreateImage(display, visual, depth, ZPixmap, 0,
                                     reinterpret_cast<char*>(pix),
                                     width, height, 32, width*4);
        XPutImage(display, window, gc, image, 0, 0, 0, 0, width, height);

        // Cleanup.
        XDestroyImage(image);

        break;
    }
  }

  // Cleanup.
  XFreeGC(display, gc);
  XCloseDisplay(display);
}
