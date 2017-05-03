#!/bin/sh

/home/massaro/src/openssh-7.5p1/sshd -ddd -e -o Port=2222 -f /etc/ssh/sshd_config -o Ciphers=aes128-ctr
#/home/massaro/src/openssh-7.5p1/sshd -D -e -o Port=2222 -f /etc/ssh/sshd_config -o Ciphers=aes128-ctr
