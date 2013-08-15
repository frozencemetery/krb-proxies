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
  printf("reqlen: %d\n", request->length);

  /* SSL init */
  SSL_library_init(); /* always returns 1 */
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  const SSL_METHOD *method = SSLv23_client_method(); /* includes TLSv1 */
  if (!method) {
    ERR_print_errors_fp(stderr);
    EVP_cleanup();
    return NULL;
  }
  SSL_CTX *gamma = SSL_CTX_new(method);
  if (!gamma) {
    ERR_print_errors_fp(stderr);
    EVP_cleanup();
    return NULL;
  }
  SSL_CTX_set_verify(gamma, SSL_VERIFY_PEER, NULL);
  if (!SSL_CTX_set_default_verify_paths(gamma)) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(gamma);
    EVP_cleanup();
    return NULL;
  }
  SSL *ssl = SSL_new(gamma);
  if (!ssl) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(gamma);
    EVP_cleanup();
    return NULL;
  }

  /* Encoding */
  char *req, *tmp;
  char *fmt = "POST /KdcProxy HTTP/1.0\r\n"
    "Cache-Control: no-cache\r\n"
    "Pragma: no-cache\r\n"
    "User-Agent: kerberos/1.0\r\n"
    "Content-type: application/kerberos\r\n"
    "Content-length: %d\r\n"
    "Host: %s\r\n"
    "\r\n";

  krb5_data *asn1 = asn1_encode(request);
  size_t reqlen = asprintf(&tmp, fmt, asn1->length, servername);
  req = malloc(reqlen + asn1->length + 1);
  memcpy(req, tmp, reqlen);
  free(tmp);
  tmp = req + reqlen;
  memcpy(tmp, asn1->data, asn1->length);
  reqlen += asn1->length;
  free(asn1->data);
  free(asn1);

  /* connect to other proxy */
  struct addrinfo khints, *kserverdata;
  memset(&khints, 0, sizeof(khints));
  khints.ai_family = AF_UNSPEC;
  khints.ai_socktype = SOCK_STREAM;   /* TCP for HTTP */
  int gai_ret = getaddrinfo(servername, port, &khints, &kserverdata);
  if (gai_ret) {
    fprintf(stderr, "%s\n", gai_strerror(gai_ret));
    SSL_CTX_free(gamma);
    EVP_cleanup();
    free(req);
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
    SSL_CTX_free(gamma);
    EVP_cleanup();
    free(req);
    return NULL;
  }

  /* SSL the socket */
  if (!SSL_set_fd(ssl, fd_prox)) {
    ERR_print_errors_fp(stderr);
    close(fd_prox);
    free(req);
    SSL_free(ssl);
    SSL_CTX_free(gamma);
    EVP_cleanup();
    return NULL;
  }
  if (SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr); /* maybe? */
    close(fd_prox);
    free(req);
    SSL_free(ssl);
    SSL_CTX_free(gamma);
    EVP_cleanup();
    return NULL;
  }

  /* send, get the KDCPROXY's reply */
  if (!SSL_write(ssl, req, reqlen)) {
    ERR_print_errors_fp(stderr); /* maybe */
    close(fd_prox);
    SSL_free(ssl);
    SSL_CTX_free(gamma);
    EVP_cleanup();
    return NULL;
  }
  free(req);

  char buf[BUF_SIZE];
  char *bufptr = buf;
  int length;
  do {
    length = SSL_read(ssl, bufptr, BUF_SIZE - 1 + bufptr - buf);
    printf("length: %d\n", length);
    if (length < 0) {
      ERR_print_errors_fp(stderr); /* maybe? */
      close(fd_prox);
      SSL_free(ssl);
      SSL_CTX_free(gamma);
      EVP_cleanup();
      return NULL;
    }
    bufptr += length;
  } while (length > 0);
  *bufptr = '\0';

  close(fd_prox);
  SSL_free(ssl);
  SSL_CTX_free(gamma);
  EVP_cleanup();

  /* forward the reply to the requester */
  char *rep = strstr(buf, "\r\n\r\n");
  if (rep == NULL) {
    fprintf(stderr, "didn't get back krb response from proxy\n");
    return NULL;
  }
  rep += 4;

  krb5_data *response = asn1_decode((unsigned char *) rep);
  return response;
}

krb5_data *krb5_cproxy_listen(int fd) {
  krb5_data *request = malloc(sizeof(krb5_data));
  request->data = malloc(BUF_SIZE*sizeof(char));
  request->length = recv(fd, request->data, BUF_SIZE - 1, 0);
  (request->data)[request->length] = '\0';
  return request;
}

int krb5_cproxy_respond(int fd_connector, krb5_data *response) {
  if (send(fd_connector, response->data, response->length, 0) == -1) {
    fprintf(stderr, "problem forwarding message\n");
    return -1;
  }
  return 0;
}

/* for forking off listeners */
void sigchild_handler(int a) {
  while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: client servername\n");
    return 1;
  }
  char *servername = argv[1];

  printf("Listening (TCP) on behalf of %s on port %s...\n", servername, "88");

  /* listen on localhost */
  struct addrinfo hints, *serverdata;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  int gai_ret = getaddrinfo(NULL, "88", &hints, &serverdata);
  if (gai_ret) {
    fprintf(stderr, "%s\n", gai_strerror(gai_ret));
    return 1;
  }

  int fd_socket = -1;
  int reuseaddr = 1;
  for (struct addrinfo *cur = serverdata;
       fd_socket == -1 && cur != NULL;
       cur = cur->ai_next) {
    fd_socket = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
    if (fd_socket == -1) {
      fprintf(stderr, "failed to socket\n");
    } else if (setsockopt(fd_socket, SOL_SOCKET, SO_REUSEADDR,
                          &reuseaddr, sizeof(int)) == -1) {
      close(fd_socket);
      fd_socket = -1;
      fprintf(stderr, "setsockopt failure\n");
    } else if (bind(fd_socket, cur->ai_addr, cur->ai_addrlen) == -1) {
      fprintf(stderr, "failed to bind\n");
      close(fd_socket);
      fd_socket = -1;
    }
  }
  freeaddrinfo(serverdata);
  if (fd_socket == -1) {
    fprintf(stderr, "unable to acquire a socket\n");
    return 1;
  }

  if (listen(fd_socket, NUM_PENDING) == -1) {
    fprintf(stderr, "failed to listen\n");
    close(fd_socket);
    return 1;
  }

  /* install a sigchild handler so that we can fork off listeners */
  struct sigaction sa;
  sa.sa_handler = sigchild_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    fprintf(stderr, "failed to install signal handler\n");
    return 1;
  }

  printf("waiting for connections...\n");
  while (1) {
    int fd_connector = accept(fd_socket, NULL, NULL);
    if (fd_connector == -1) {
      fprintf(stderr, "failed to accept\n");
      continue;
    }
    printf("connection!  Spawning child...\n");

    int fval;
    for (fval = fork(); fval == -1; fval = fork()) {
      fprintf(stderr, "failed to fork; retrying\n");
      sleep(1); /* spin */
    }
    if (!fval) { /* child */
      close(fd_socket);

      krb5_data *request = krb5_cproxy_listen(fd_connector);
      krb5_data *response = krb5_cproxy_process(servername, "443", request);
      free(request->data);
      free(request);

      int rval = krb5_cproxy_respond(fd_connector, response);
      free(response->data);
      free(response);

      if (rval) {
        fprintf(stderr, "error in proxying\n");
      }

      close(fd_connector);

      printf("child exit\n");
      return 0;
    }
    close(fd_connector);
  }

  close(fd_socket);

  return 0;
}
