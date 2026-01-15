#!/bin/bash

set -e

GOARCH=arm64 GOOS=darwin go build -trimpath -o bin/darwin/
GOARCH=amd64 GOOS=linux go build -trimpath -o bin/linux/
GOARCH=amd64 GOOS=windows go build -trimpath -o bin/windows/
