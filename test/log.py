#!/usr/bin/env python3

import sys
import os
import logging

from config import config

""" @var formatting delimiter consisting of '=' characters """
double_line_delim = '=' * 78
""" @var formatting delimiter consisting of '-' characters """
single_line_delim = '-' * 78


def colorize(msg, color):
    return f"{color}{msg}{COLOR_RESET}"


class ColorFormatter(logging.Formatter):

    def init(self, fmt=None, datefmt=None):
        super(ColorFormatter, self).__init__(fmt, datefmt)

    def format(self, record):
        message = super(ColorFormatter, self).format(record)
        if hasattr(record, 'color'):
            message = colorize(message, record.color)
        return message


# 40 = ERROR, 30 = WARNING, 20 = INFO, 10 = DEBUG, 0 = NOTSET (all messages)
if config.verbose >= 2:
    log_level = 10
elif config.verbose == 1:
    log_level = 20
else:
    log_level = 40

handler = logging.StreamHandler(sys.stdout)
color_formatter = ColorFormatter(fmt='%(asctime)s,%(msecs)03d %(message)s',
                                 datefmt="%H:%M:%S")
handler.setFormatter(color_formatter)
handler.setLevel(log_level)

global_logger = logging.getLogger()
global_logger.addHandler(handler)

scapy_logger = logging.getLogger("scapy.runtime")
scapy_logger.setLevel(logging.ERROR)


def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    return logger


def get_parallel_logger(stream):
    logger = logging.getLogger('parallel_logger_{!s}'.format(stream))
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(color_formatter)
    handler.setLevel(log_level)
    logger.addHandler(handler)
    return logger


# Static variables to store color formatting strings.
#
# These variables (RED, GREEN, YELLOW and LPURPLE) are used to configure
# the color of the text to be printed in the terminal. Variable COLOR_RESET
# is used to revert the text color to the default one.
if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    LPURPLE = '\033[94m'
    COLOR_RESET = '\033[0m'
else:
    RED = ''
    GREEN = ''
    YELLOW = ''
    LPURPLE = ''
    COLOR_RESET = ''
