#!/bin/bash

gcc -O3 -Wall -Wextra -o attack sol.c -lnet -lpcap
