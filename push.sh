#!/bin/bash

if [ $# -ne 1 ]; then
  echo "Usage: ./push.sh commit_message"
  exit 1  # Exit with a non-zero status code to indicate an error
fi

git add .
git commit -m "$1"  # Enclose $1 in double quotes to capture the commit message with spaces
git push

