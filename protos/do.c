/*-
  Copyright (C) 2014 Mikolaj Izdebski

  This is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This software is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with lbzip2. If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


/*#define Trace(x) printf x*/
#define Trace(x)


static int
xopen(const char *fn, int flags)
{
  int fd = open(fn, flags);
  if (fd < 0)
    err(1, "open: %s", fn);
  return fd;
}
#define open xopen

static void
xclose(int fd)
{
  if (close(fd) < 0)
    err(1, "close");
}
#define close xclose

static void
xdup2(int fd1, int fd2)
{
  if (dup2(fd1, fd2) < 0)
    err(1, "dup2");
}
#define dup2 xdup2

static void
xpipe(int fds[2])
{
  if (pipe(fds) < 0)
    err(1, "pipe");

}
#define pipe xpipe

static pid_t
xfork(void)
{
  pid_t pid = fork();
  if (pid == (pid_t)-1)
    err(1, "fork");
  return pid;
}
#define fork xfork

static void *
xmalloc(size_t size)
{
  void *ptr = malloc(size);
  if (ptr == NULL)
    err(1, "malloc");
  return ptr;
}
#define malloc xmalloc


struct test {
  char id[33];
  char md5[16];
  int expect_failure;
  off_t blob_offset;
  size_t blob_size;
};

struct child {
  pid_t pid;
  int alive;
  int status;
  struct child *next, *prev;
  MD5_CTX md5_ctx;
  int in_fd;
  int out_fd;
  int err_fd;
  struct test *test;
  int error_message_printed;
  char *write_ptr;
  char *write_end;
};

char *blob;
struct test *tests;
struct test *next_test;
struct child *childreen = NULL;
unsigned alive_childreen = 0;
unsigned num_childreen = 0;
unsigned max_childreen = 8;
unsigned num_tests;
unsigned num_fail;

static void
fail(struct test *test, const char *reason)
{
  (void)test;
  num_fail++;

  printf("FAILURE: [%s]: %s\n", test->id, reason);
}


static void
succeed(struct test *test)
{
  (void)test;

  Trace(("SUCCESS\n"));
}



char *cmd[] = { COMMAND_ARGV, (char *)0 };
char *env[] = { COMMAND_ENVIRON, (char *)0 };

static void
reaper(int sig)
{
  pid_t pid;
  int status;
  struct child *child;

  (void)sig;

  while (alive_childreen > 0 && (pid = waitpid((pid_t)-1, &status, WNOHANG)) > 0) {
    if (!WIFEXITED(status) && !WIFSIGNALED(status))
      continue;
    for (child = childreen; child != NULL && child->pid != pid; child = child->next)
      ;
    if (child == NULL)
      abort();
    child->status = status;
    child->alive = 0;
    alive_childreen--;
  }
}

int
main()
{
  int fd;
  pid_t pid;
  struct test *test;
  struct child *child;
  unsigned char md5[16];
  char buf[BUFSIZ];
  char last_percentage[BUFSIZ];
  ssize_t go;
  ssize_t sz;
  fd_set read_set;
  fd_set write_set;
  sigset_t blocked;
  sigset_t handled;
  sigset_t saved;
  struct timespec *timeout = NULL;
  struct stat stat;
  unsigned i;
  unsigned j;
  off_t offset;

  fd = open("control", O_RDONLY);
  fstat(fd, &stat);
  if (stat.st_size % 76 != 0)
    errx(1, "control file size not modulo 76");
  num_tests = stat.st_size / 76;
  tests = malloc((num_tests + 1) * sizeof(struct test));
  bzero(tests, (num_tests + 1) * sizeof(struct test));
  test = tests;
  Trace(("%u tests available\n", num_tests));

  offset = 0;
  for (i = 0; i < num_tests; i++) {
    go = 76;
    while (go > 0 && (sz = read(fd, buf + 76 - go, go)) > 0)
      go -= sz;
    if (go != 0)
      errx(1, "Incomplete control file");
    buf[32] = 0;
    buf[42] = 0;
    strcpy(test->id, buf);
    test->blob_offset = offset;
    test->blob_size = atol(buf+33);
    if (buf[43] != '-') {
      for (j = 0; j < 16; j++) {
	const char *st = "0123456789abcdef";
	unsigned hi = index(st, buf[43+2*j]) - st;
	unsigned lo = index(st, buf[44+2*j]) - st;
	test->md5[j] = 16*hi + lo;
      }
    }
    else {
      test->expect_failure = 1;
    }
    offset += test->blob_size;
    test++;
  }
  close(fd);

  fd = open("blob", O_RDONLY);
  fstat(fd, &stat);
  if (stat.st_size != offset)
    errx(1, "blob size does not match control file");
  blob = mmap(0, offset, PROT_READ, MAP_SHARED, fd, 0);
  madvise(blob, offset, MADV_SEQUENTIAL);

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);

  sigemptyset(&blocked);
  sigaddset(&blocked, SIGPIPE);
  sigprocmask(SIG_BLOCK, &blocked, NULL);
  sigemptyset(&handled);
  sigaddset(&handled, SIGCHLD);
  sigprocmask(SIG_BLOCK, &handled, &saved);
  signal(SIGCHLD, reaper);

  next_test = tests;

  for (;;) {
    /* Read stdout. */
    for (child = childreen; child != NULL; child = child->next) {
      if (child->out_fd < 0 || !FD_ISSET(child->out_fd, &read_set))
	continue;
      while ((sz = read(child->out_fd, buf, BUFSIZ)) > 0)
	MD5_Update(&child->md5_ctx, buf, sz);
      if (sz == 0) {
	close(child->out_fd);
	child->out_fd = -1;
      }
      else if (sz < 0 && errno != EAGAIN)
	err(1, "read");
      Trace(("Read stdout\n"));
    }

    /* Read stderr. */
    for (child = childreen; child != NULL; child = child->next) {
      if (child->err_fd < 0 || !FD_ISSET(child->err_fd, &read_set))
	continue;
      while ((sz = read(child->err_fd, buf, BUFSIZ)) > 0)
	child->error_message_printed = 1;
      if (sz == 0) {
	close(child->err_fd);
	child->err_fd = -1;
      }
      else if (sz < 0 && errno != EAGAIN)
	err(1, "read");
      Trace(("Read stderr\n"));
    }

    /* Reap dead childreen. */
    for (child = childreen; child != NULL; child = child->next) {
      if (child->alive)
	continue;

      test = child->test;

      if (child->in_fd >= 0)
	close(child->in_fd);
      if (child->out_fd >= 0)
	close(child->out_fd);
      if (child->err_fd >= 0)
	close(child->err_fd);
      MD5_Final(md5, &child->md5_ctx);

      if (WIFSIGNALED(child->status)) {
	fail(test, "Child was terminated with a signal");
      }
      else {
	if (WEXITSTATUS(child->status) != 0) {
	  if (WEXITSTATUS(child->status) == 77) {
	    printf("There was a problem running command: %s\n", COMMAND_PATH);
	    exit(77);
	  }
	  if (!test->expect_failure)
	    fail(test, "Child failed, but expected success");
	  else if (!child->error_message_printed)
	    fail(test, "Child failed, but did not print any error message");
	  else
	    succeed(test);
	} else {
	  if (test->expect_failure)
	    fail(test, "Child succeeded, but expected failure");
	  else if (child->error_message_printed && !IGNORE_VERBOSE_OUTPUT)
	    fail(test, "Child succeeded, but printed an error message");
	  else if (child->in_fd >= 0) {
	    fail(test, "Child succeeded, but did not consume all data");
	  }
	  else if (memcmp(md5, test->md5, 16) != 0)
	    fail(test, "Output MD5 mismatch");
	  else
	    succeed(test);
	}
      }

      if (child->prev)
	child->prev->next = child->next;
      if (child->next)
	child->next->prev = child->prev;
      if (childreen == child)
	childreen = child->next;
      free(child);
      num_childreen--;
      Trace(("Child reaped\n"));
    }

    /* Feed hungry childreen. */
    for (child = childreen; child != NULL; child = child->next) {
      if (child->in_fd < 0 || !FD_ISSET(child->in_fd, &write_set))
	continue;
      while (child->write_ptr < child->write_end &&
	     (sz = write(child->in_fd, child->write_ptr, child->write_end - child->write_ptr)) > 0)
	child->write_ptr += sz;
      if (sz < 0 && errno != EAGAIN) {
	if (errno == EPIPE)
	  child->write_ptr = child->write_end;
	else
	  err(1, "write");
      }
      if (child->write_end == child->write_ptr) {
	close(child->in_fd);
	child->in_fd = -1;
      }
      Trace(("Child fed\n"));
    }

    /* Kill old childreen. */

    /* Procreate new childreen. */
    while (num_childreen < max_childreen && next_test->id[0] != 0) {
      sprintf(buf, "%.2f", 100. * ((next_test + 1) - tests) / num_tests);
      if (strcmp(last_percentage, buf) != 0) {
	strcpy(last_percentage, buf);
	printf("Running test %u/%u [%s %%], %u failures\r",
	       (unsigned)((next_test + 1) - tests), num_tests, buf, num_fail);
	fflush(stdout);
      }
      int pipes[3][2];
      child = malloc(sizeof(struct child));
      child->test = next_test++;
      MD5_Init(&child->md5_ctx);
      pipe(pipes[0]);
      pipe(pipes[1]);
      pipe(pipes[2]);
      pid = fork();
      if (pid == 0) {
	dup2(pipes[0][0], STDIN_FILENO);
	dup2(pipes[1][1], STDOUT_FILENO);
	dup2(pipes[2][1], STDERR_FILENO);
      }
      close(pipes[0][0]);
      close(pipes[1][1]);
      close(pipes[2][1]);
      if (pid == 0) {
	close(pipes[0][1]);
	close(pipes[1][0]);
	close(pipes[2][0]);
	execve(COMMAND_PATH, cmd, env);
	err(77, "execve");
      }
      fcntl(pipes[0][1], F_SETFL, fcntl(pipes[0][1], F_GETFL) | O_NONBLOCK);
      fcntl(pipes[1][0], F_SETFL, fcntl(pipes[1][0], F_GETFL) | O_NONBLOCK);
      fcntl(pipes[2][0], F_SETFL, fcntl(pipes[2][0], F_GETFL) | O_NONBLOCK);
      child->alive = 1;
      child->pid = pid;
      child->write_ptr = blob + child->test->blob_offset;
      child->write_end = child->write_ptr + child->test->blob_size;
      child->in_fd = pipes[0][1];
      child->out_fd = pipes[1][0];
      child->err_fd = pipes[2][0];
      child->error_message_printed = 0;
      if (childreen != NULL)
	childreen->prev = child;
      child->next = childreen;
      child->prev = NULL;
      childreen = child;
      num_childreen++;
      alive_childreen++;
      Trace(("Child born\n"));
    }

    if (num_childreen == 0 && next_test->id[0] == 0)
      break;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    for (child = childreen; child != NULL; child = child->next) {
      if (child->in_fd >= 0)
	FD_SET(child->in_fd, &write_set);
      if (child->out_fd >= 0)
	FD_SET(child->out_fd, &read_set);
      if (child->err_fd >= 0)
	FD_SET(child->err_fd, &read_set);
    }
    Trace(("Waiting\n"));
    pselect(FD_SETSIZE, &read_set, &write_set, NULL, timeout, &saved);
  }

  printf("                                          \r");
  printf("Test run finished.");
  printf("Thedre were %u failures.", num_fail);
  return 0;
}
