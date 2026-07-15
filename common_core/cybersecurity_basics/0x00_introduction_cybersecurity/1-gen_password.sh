#!/bin/bash
tr -cd '[:alnum:]' < /dev/urandom | fold -w"$1" | head -n 1
