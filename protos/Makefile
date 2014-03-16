IGNORE_VERBOSE_OUTPUT = 0
COMMAND_PATH          = '"./lbzip2"'
COMMAND_ARGV          = '"lbzip2", "-dcn1"'
COMMAND_ENVIRON       = '""'

CC      = gcc
CFLAGS  = -O2 -g3 -Wall -W
LDFLAGS = -lcrypto

run-tests: do.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DIGNORE_VERBOSE_OUTPUT=$(IGNORE_VERBOSE_OUTPUT) -DCOMMAND_PATH=$(COMMAND_PATH) -DCOMMAND_ARGV=$(COMMAND_ARGV) -DCOMMAND_ENVIRON=$(COMMAND_ENVIRON) -o $@ $<

clean:
	@rm -f run-tests
