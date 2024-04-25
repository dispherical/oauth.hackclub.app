#!/bin/bash
# This must be added to visudo so all users may use it.

NEST_USER=$(sudo who am i | awk '{print $1}')

sudo curl --unix-socket /home/david/oauth.hackclub.app/.localauth.socket http://localhost/authorize/$NEST_USER