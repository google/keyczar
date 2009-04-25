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

#include <windows.h>
#include "cross/mandelbrot_generator.h"

static const char *kClassName = "mandelbrot";
static const int kSizingTimeout = 500;

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg,
                                   WPARAM wParam, LPARAM lParam) {
  static unsigned char *pix = 0;
  static int pix_width = 0;
  static int pix_height = 0;
  static bool stale = true;

  switch (uMsg) {
    case WM_CLOSE:
      PostQuitMessage(0);
      return 0;

    case WM_DESTROY:
      if (pix) delete[] pix;
      return 0;

    case WM_EXITSIZEMOVE:
      stale = true;
      InvalidateRect(hwnd, NULL, FALSE);
      return 0;

    case WM_PAINT:
      // Get client area size
      RECT rect;
      GetClientRect(hwnd, &rect);
      int width = rect.right - rect.left;
      int height = rect.bottom - rect.top;

      // Render image if size has changed and not resizing.
      if (!pix || stale) {
        // Dump old if any.
        if (pix) delete[] pix;

        // Render image.
        pix = new unsigned char[width * height * 4];
        pix_width = width;
        pix_height = height;
        MandelbrotGenerator m;
        m.DemoFocus();
        m.Render(width, height, pix);

        // No longer stale.
        stale = false;
      }

      // Prepare bitmap structure.
      BITMAPINFO bi;
      ZeroMemory(&bi, sizeof(bi));
      BITMAPINFOHEADER *bh = &bi.bmiHeader;
      bh->biSize = sizeof(bi.bmiHeader);
      bh->biWidth = pix_width;
      bh->biHeight = -pix_height;
      bh->biPlanes = 1;
      bh->biBitCount = 32;
      bh->biCompression = BI_RGB;

      // Draw image.
      PAINTSTRUCT ps;
      HDC hdc = BeginPaint(hwnd, &ps);
      SetStretchBltMode(hdc, COLORONCOLOR);
      StretchDIBits(hdc, 0, 0, width, height,
                    0, 0, pix_width, pix_height,
                    pix, &bi, DIB_RGB_COLORS, SRCCOPY);
      EndPaint(hwnd, &ps);

      return 0;
  }

  return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  // Create the main window class.
  WNDCLASS wc;
  ZeroMemory(&wc, sizeof(wc));
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = hInstance;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.lpszClassName = kClassName;
  RegisterClass(&wc);

  // Create main window.
  HWND hwnd = CreateWindow(kClassName, "Mandelbrot Set Sample",
                           WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT,
                           500, 400, NULL, NULL, hInstance, NULL);
  ShowWindow(hwnd, nCmdShow);
  UpdateWindow(hwnd);

  // Main message handling loop.
  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0) >0) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return msg.wParam;
}
