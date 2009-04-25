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

#import "mac/ImageGeneratorView.h"
#import <AppKit/NSBitmapImageRep.h>

@implementation ImageGeneratorView

- (void)dealloc {
  [lastImage_ release];
  [self setImageSource:nil];
  [super dealloc];
}

- (void)viewDidEndLiveResize {
  [self setNeedsDisplay:YES];
}

- (void)drawRect:(NSRect)rect {
  // Do nothing if there is no source.
  if (!imageSource_) return;

  // Only create image if not resizing or to start out with.
  if (!lastImage_ || ![self inLiveResize]) {
    // drop the last one
    [lastImage_ release];

    int width = rect.size.width;
    int height = rect.size.height;

    NSBitmapImageRep *imageRep = [[NSBitmapImageRep alloc]
        initWithBitmapDataPlanes:NULL
                      pixelsWide:width
                      pixelsHigh:height
                   bitsPerSample:8
                 samplesPerPixel:4
                        hasAlpha:YES
                        isPlanar:NO
                  colorSpaceName:NSCalibratedRGBColorSpace
                     bytesPerRow:width*4
                    bitsPerPixel:0];

    // Render the image.
    imageSource_->Render(width, height, [imageRep bitmapData]);

    lastImage_ = [[NSImage alloc] init];
    [lastImage_ addRepresentation:imageRep];

    [imageRep release];
  }

  // Actually draw the image.
  [lastImage_ drawInRect:rect fromRect:NSZeroRect
      operation:NSCompositeCopy fraction:1.0];
}

- (void)setImageSource:(ImageGeneratorInterface *)source {
  if (imageSource_) delete imageSource_;
  imageSource_ = source;
}

@end
