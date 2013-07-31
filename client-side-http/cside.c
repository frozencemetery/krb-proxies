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

#include "cside.h"

krb5_data *
krb5_cproxy_process(char *servername, char *port, krb5_data *request) {
  /* turn it into HTTP for the KDCPROXY */
  char *req;
  char *fmt = "POST / HTTP/1.0\r\n"
    "Content-type: application/kerberos\r\n"
    "Content-length: %d\r\n"
    "\r\n%s";
  char *g_buf = g_base64_encode((guchar *) request->data, request->length);
  size_t reqlen = asprintf(&req, fmt, strlen(g_buf), g_buf);
  g_free(g_buf);

  /* connect to other proxy */
  struct addrinfo khints, *kserverdata;
  memset(&khints, 0, sizeof(khints));
  khints.ai_family = AF_UNSPEC;
  khints.ai_socktype = SOCK_STREAM;   /* TCP for HTTP */
  int gai_ret = getaddrinfo(servername, port, &khints, &kserverdata);
  if (gai_ret) {
    fprintf(stderr, "%s\n", gai_strerror(gai_ret));
    return NULL;
  }

  int fd_prox = -1;
  for (struct addrinfo *cur = kserverdata;
       cur != NULL && fd_prox == -1;
       cur = cur->ai_next) {
    fd_prox = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
    if (fd_prox == -1) {
      fprintf(stderr, "failed to socket\n");
    } else if (connect(fd_prox, cur->ai_addr, cur->ai_addrlen) == -1) {
      close(fd_prox);
      fd_prox = -1;
      fprintf(stderr, "failed to connect\n");
    }
  }
  freeaddrinfo(kserverdata);
  if (fd_prox == -1) {
    fprintf(stderr, "unable to connect to any sockets\n");
    return NULL;
  }

  /* send, get the KDCPROXY's reply */
  if (send(fd_prox, req, reqlen, 0) == -1) {
    fprintf(stderr, "problem sending message\n");
    free(req);
    close(fd_prox);
    return NULL;
  }

  free(req);

  char buf[BUF_SIZE];
  int length = recv(fd_prox, buf, BUF_SIZE - 1, MSG_WAITALL);
  if (length == -1) {
    fprintf(stderr, "error on second recv in child\n");
    close(fd_prox);
    return NULL;
  }
  buf[length] = '\0';
  close(fd_prox);

  /* forward the reply to the requester */
  char *rep = strstr(buf, "\r\n\r\n");
  if (rep == NULL) {
    fprintf(stderr, "didn't get back krb response from proxy\n");
    return NULL;
  }
  rep += 4;

  gsize out_len;
  guchar *res = g_base64_decode(rep, &out_len);

  krb5_data *response = malloc(sizeof(krb5_data));
  response->length = out_len;
  response->data = malloc(sizeof(char)*(out_len + 1));
  memcpy(response->data, res, out_len);
  (response->data)[out_len] = '\0';

  g_free(res);
  return response;
}
