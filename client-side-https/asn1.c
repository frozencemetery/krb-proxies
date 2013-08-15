/*
 * Copyright (C) 2013, Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of Red Hat, Inc., nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "asn1.h"

krb5_data *asn1_encode(krb5_data *raw) {
  krb5_data *enc = malloc(sizeof(krb5_data));

  int len1 = raw->length;
  int str1len = 1 +
    (len1 > (1 << 7) ? (len1 + 254) / 255 : 0);

  int len2 = len1 + str1len + 1;
  int str2len = 1 +
    (len2 > (1 << 7) ? (len2 + 254) / 255 : 0);

  int len3 = len2 + str2len + 1 + 12;
  int str3len = 1 +
    (len3 > (1 << 7) ? (len3 + 254) / 255 : 0);

  enc->length = len3 + str3len + 1;
  enc->data = malloc(enc->length + 1);
  enc->data[enc->length] = '\0';
  char *ptr = enc->data;

  *ptr = '\x30';
  ptr++;
  if (str3len == 1) {
    *ptr = (char) (len3);
    ptr++;
  } else {
    str3len--;
    *ptr = 0x80 | str3len;
    ptr++;
    while (str3len > 0) {
      *ptr = (char) (len3 >> (8*(str3len - 1)));
      ptr++;
      str3len--;
    }
  }
  *ptr = '\xa0';
  ptr++;
  if (str2len == 1) {
    *ptr = (char) (len2);
    ptr++;
  } else {
    str2len--;
    *ptr = 0x80 | str2len;
    ptr++;
    while (str2len > 0) {
      *ptr = (char) (len2 >> (8*(str2len - 1)));
      ptr++;
      str2len--;
    }
  }
  *ptr = '\x04';
  ptr++;
  if (str1len == 1) {
    *ptr = (char) (len1);
    ptr++;
  } else {
    str1len--;
    *ptr = 0x80 | str1len;
    ptr++;
    while (str1len > 0) {
      *ptr = (char) (len1 >> (8*(str1len - 1)));
      ptr++;
      str1len--;
    }
  }
  memcpy(ptr, raw->data, raw->length);
  ptr += raw->length;

  char *magic = "\xa1\x0a\x1b\x08mkad2012";
  memcpy(ptr, magic, 12);

  return enc;
}

krb5_data *asn1_decode(unsigned char *enc) {
  if (*enc != 0x30) {
    return NULL;
  }
  enc++;
  int str3len = 1 + (*enc > 0x80 ? *enc & ~0x80 : 0);
  int len3 = 0;
  if (str3len == 1) {
    len3 = *enc;
  } else {
    str3len--;
    while (str3len > 0) {
      enc++;
      len3 <<= 8;
      len3 |= *enc;
      str3len--;
    }
  }
  enc++;

  if (*enc != 0xa0) {
    return NULL;
  }
  enc++;
  int str2len = 1 + (*enc > 0x80 ? *enc & ~0x80 : 0);
  int len2 = 0;
  if (str2len == 1) {
    len2 = *enc;
  } else {
    str2len--;
    while (str2len > 0) {
      enc++;
      len2 <<= 8;
      len2 |= *enc;
      str2len--;
    }
  }
  enc++;

  if (*enc != 0x04) {
    return NULL;
  }
  enc++;
  int str1len = 1 + (*enc > 0x80 ? *enc & ~0x80 : 0);
  int len1 = 0;
  if (str1len == 1) {
    len1 = *enc;
  } else {
    str1len--;
    while (str1len > 0) {
      enc++;
      len1 <<= 8;
      len1 |= *enc;
      str1len--;
    }
  }
  enc++;

  krb5_data *raw = malloc(sizeof(krb5_data));
  raw->length = len1;
  raw->data = malloc(len1);
  memcpy(raw->data, enc, len1);

  return raw;
}
