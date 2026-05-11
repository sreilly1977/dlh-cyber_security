#!/bin/bash
addgroup $1
chown :$2 $1
chmod g+rx $2
