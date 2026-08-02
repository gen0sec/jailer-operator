#!/bin/sh
# The builder image must satisfy go.mod. They drifted once: a dependency
# alignment moved go.mod to a newer Go while the Dockerfile kept an older
# builder, so the image failed to build while every other check stayed green.
set -eu
want=$(awk '/^go /{print $2}' go.mod | cut -d. -f1,2)
have=$(awk '/^FROM golang:/{sub("FROM golang:","");sub(" .*","");print;exit}' Dockerfile | cut -d. -f1,2)
if [ "$want" != "$have" ]; then
  echo "go.mod requires Go $want but Dockerfile builds with $have"
  exit 1
fi
echo "Go version in sync: $want"
