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

int main() {
  krb5_data input;
  input.data =
    "multas per gentes et multa per aequora vectus\n"
    "advenio has miseras frater ad inferias\n"
    "ut te postremo donarem munere mortis\n"
    "et mutam nequiquam alloquerer cinerem\n"
    "quandoquidem fortuna mihi tete abstulit ipsum\n"
    "heu miser indigne frater adempte mihi\n"
    "nunc tamen interea haec prisco quae more parentum\n"
    "tradita sunt tristi munere ad inferias\n"
    "accipe fraterno multum manantia fletu\n"
    "atque in perpetuum frater ave atque vale\n"
    "\n";
  input.length = strlen(input.data);

  krb5_data *enc = asn1_encode(&input);
  krb5_data *raw = asn1_decode((unsigned char *) enc->data);

  printf("%s\n", raw->data);

  return 0;
}
