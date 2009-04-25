/* -*- mode: c++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*- */
/* vi: set expandtab shiftwidth=4 tabstop=4: */

/**
 * \file
 * <PRE>
 * High performance WEB-SAFE base64 encoder / decoder
 *
 * Copyright &copy; 2005, 2006, 2007 Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 *
 * http://code.google.com/p/stringencoders/
 *
 * Released under bsd license.  See modp_b64w.c for details.
 * </pre>
 *
 * This uses a "URL-safe" or "WEB-safe" encoding.  THe standard
 * base 64 encoding uses the characters '+', '/' and '=' have special
 * restrictions when used inside a URL.
 *
 * This uses "+" to "-", "/" to "_", and "=" to "." as the replacement
 * alphabet.
 *
 * It's easy to change this to use "URL safe" characters and to remove
 * padding.  See the modp_b64.c source code for details.
 *
 */

#ifndef COM_MODP_STRINGENCODERS_B64W
#define COM_MODP_STRINGENCODERS_B64W

#ifdef __cplusplus
#define BEGIN_C extern "C" {
#define END_C }
#else
#define BEGIN_C
#define END_C
#endif

BEGIN_C

/**
 * Encode a raw binary string into web-safe base 64.
 * \param[out] dest should be allocated by the caller to contain
 *   at least modp_b64w_encode_len(len) bytes (see below)
 *   This will contain the null-terminated b64w encoded result
 * \param[in] src contains the bytes
 * \param[in] len contains the number of bytes in the src
 * \return length of the destination string plus the ending null byte
 *    i.e.  the result will be equal to strlen(dest) + 1
 *
 * Example
 *
 * \code
 * char* src = ...;
 * int srclen = ...; //the length of number of bytes in src
 * char* dest = (char*) malloc(modp_b64w_encode_len);
 * int len = modp_b64w_encode(dest, src, sourcelen);
 * if (len == -1) {
 *   printf("Error\n");
 * } else {
 *   printf("b64w = %s\n", dest);
 * }
 * \endcode
 *
 */
int modp_b64w_encode(char* dest, const char* src, int len);

/**
 * Decode a web-safe base64 encoded string
 *
 * \param[out] dest should be allocated by the caller to contain at least
 *    len * 3 / 4 bytes.
 * \param[in] src should contain exactly len bytes of b64w characters.
 *     if src contains -any- non-base characters (such as white
 *     space, -1 is returned.
 * \param[in] len is the length of src
 *
 * \return the length (strlen) of the output, or -1 if unable to
 * decode
 *
 * \code
 * char* src = ...;
 * int srclen = ...; // or if you don't know use strlen(src)
 * char* dest = (char*) malloc(modp_b64w_decode_len(srclen));
 * int len = modp_b64w_decode(dest, src, sourcelen);
 * if (len == -1) { error }
 * \endcode
 */
int modp_b64w_decode(char* dest, const char* src, int len);

/**
 * Given a source string of length len, this returns the amount of
 * memory the destination string should have.
 *
 * remember, this is integer math
 * 3 bytes turn into 4 chars
 * ceiling[len / 3] * 4 + 1
 *
 * +1 is for any extra null.
 */
#define modp_b64w_encode_len(A) ((A+2)/3 * 4 + 1)

/**
 * Given a base64 string of length len,
 *   this returns the amount of memory required for output string
 *  It maybe be more than the actual number of bytes written.
 * NOTE: remember this is integer math
 * this allocates a bit more memory than traditional versions of b64w
 * decode  4 chars turn into 3 bytes
 * floor[len * 3/4] + 2
 */
#define modp_b64w_decode_len(A) (A / 4 * 3 + 2)

/**
 * Will return the strlen of the output from encoding.
 * This may be less than the required number of bytes allocated.
 *
 * This allows you to 'deserialized' a struct
 * \code
 * char* b64wencoded = "...";
 * int len = strlen(b64wencoded);
 *
 * struct datastuff foo;
 * if (modp_b64w_encode_strlen(sizeof(struct datastuff)) != len) {
 *    // wrong size
 *    return false;
 * } else {
 *    // safe to do;
 *    if (modp_b64w_decode((char*) &foo, b64wencoded, len) == -1) {
 *      // bad characters
 *      return false;
 *    }
 * }
 * // foo is filled out now
 * \endcode
 */
#define modp_b64w_encode_strlen(A) ((A + 2)/ 3 * 4)

END_C

#ifdef __cplusplus
#include <cstring>
#include <string>

namespace modp {

    /** \brief b64w encode a cstr with len
     *
     * \param[in] s the input string to encode
     * \param[in] len the length of the input string
     * \return a newly allocated b64w string.  Empty if failed.
     */
    inline std::string b64w_encode(const char* s, size_t len)
    {
        std::string x(modp_b64w_encode_len(len), '\0');
        int d = modp_b64w_encode(const_cast<char*>(x.data()), s,
                                 static_cast<int>(len));
        x.erase(d, std::string::npos);
        return x;
    }

    /** \brief b64w encode a cstr
     *
     * \param[in] s the input string to encode
     * \return a newly allocated b64w string.  Empty if failed.
     */
    inline std::string b64w_encode(const char* s)
    {
        return b64w_encode(s, static_cast<int>(strlen(s)));
    }

    /** \brief b64w encode a const std::string
     *
     * \param[in] s the input string to encode
     * \return a newly allocated b64w string.  Empty if failed.
     */
    inline std::string b64w_encode(const std::string& s)
    {
        return b64w_encode(s.data(), s.size());
    }

    /** \brief self-modifing b64w encode
     *
     * web-safe base 64 decode a string (self-modifing)
     * On failure, the string is empty.
     *
     * \param[in,out] s the string to be decoded
     * \return a reference to the input string
     */
    inline std::string& b64w_encode(std::string& s)
    {
        std::string x(b64w_encode(s.data(), s.size()));
        s.swap(x);
        return s;
    }

    inline std::string b64w_decode(const char* src, size_t len)
    {
        std::string x(modp_b64w_decode_len(len)+1, '\0');
        int d = modp_b64w_decode(const_cast<char*>(x.data()), src,
                                 static_cast<int>(len));
        if (d < 0) {
            x.clear();
        } else {
            x.erase(d, std::string::npos);
        }
        return x;
    }

    inline std::string b64w_decode(const char* src)
    {
        return b64w_decode(src, strlen(src));
    }

    /**
     * base 64 decode a string (self-modifing)
     * On failure, the string is empty.
     *
     * This function is for C++ only (duh)
     *
     * \param[in,out] s the string to be decoded
     * \return a reference to the input string
     */
    inline std::string& b64w_decode(std::string& s)
    {
        std::string x(b64w_decode(s.data(), s.size()));
        s.swap(x);
        return s;
    }

    inline std::string b64w_decode(const std::string& s)
    {
        return b64w_decode(s.data(), s.size());
    }
}

#endif /* __cplusplus */

#endif /* MODP_B64W */

