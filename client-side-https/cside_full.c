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

#include "cside_full.h"

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
