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

#define BUFSNEEDED(i) (1 + ((i) > (1 << 7) ? ((i) + 254) / 255 : 0))

/* Request structure:
 * '\x30' <len[0]>
 *        '\xa0' <len[1]>
 *               '\x04' <len[2]>
 *                      <raw->data>
 *        '\xa1' <len[3]>
 *               '\x1b' <len[4]>
 *                      <realm>
 */
const unsigned char magic[] = "\x30\xa0\x04\xa1\x1b"; /* ASN.1 tags */

void asn1_writeout(char **pptr, int *lenlen, int *len, int i) {
  char *ptr = *pptr;
  *ptr = magic[i];
  ptr++;

  if (lenlen[i] == 1) {
    *ptr = (char) (len[i]);
    ptr++;
  } else {
    lenlen[i]--;
    *ptr = 0x80 | lenlen[i];
    ptr++;
    while (lenlen[i] > 0) {
      *ptr = (char) (len[i] >> (8*(lenlen[i] - 1)));
      ptr++;
      lenlen[i]--;
    }
  }

  *pptr = ptr;
  return;
}

krb5_data *asn1_encode(krb5_data *raw, char *realm) {
  int len[5], lenlen[5];

  len[2] = raw->length;
  lenlen[2] = BUFSNEEDED(len[2]);

  len[1] = len[2] + lenlen[2] + 1;
  lenlen[1] = BUFSNEEDED(len[1]);

  len[4] = strlen(realm);
  lenlen[4] = BUFSNEEDED(len[4]);

  len[3] = len[4] + lenlen[4] + 1;
  lenlen[3] = BUFSNEEDED(len[3]);

  len[0] = len[1] + len[4] + lenlen[1] + lenlen[3] + lenlen[4] + 3;
  lenlen[0] = BUFSNEEDED(len[0]);

  krb5_data *enc = malloc(sizeof(krb5_data));
  enc->length = len[0] + lenlen[0] + 1;
  enc->data = malloc(enc->length + 1);
  char *ptr = enc->data;

  for (int i = 0; i <= 4; i++) {
    asn1_writeout(&ptr, lenlen, len, i);
    if (i == 2) {
      memcpy(ptr, raw->data, raw->length);
      ptr += raw->length;
    } else if (i == 4) {
      memcpy(ptr, realm, strlen(realm));
      ptr += strlen(realm);
    }
  }

  enc->data[enc->length] = '\0';
  return enc;
}

krb5_data *asn1_decode(unsigned char *enc) {
  int len[5], lenlen[5];

  for (int i = 0; i <= 2; i++) {
    if (*enc != magic[i]) {
      return NULL;
    }
    enc++;

    lenlen[i] = 1 + (*enc > 0x80 ? *enc & ~0x80 : 0);
    if (lenlen[i] == 1) {
      len[i] = *enc;
    } else {
      for (len[i] = 0; lenlen[i] > 1; lenlen[i]--) {
        enc++;
        len[i] <<= 8;
        len[i] |= *enc;
      }
    }
    enc++;
  }

  krb5_data *raw = malloc(sizeof(krb5_data));
  raw->length = len[2];
  raw->data = malloc(len[2]);
  memcpy(raw->data, enc, len[2]);

  /* discard the remainder of the contents */

  return raw;
}
