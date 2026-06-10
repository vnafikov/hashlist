#!/bin/sh

export GOEXPERIMENT=

GOARCH=amd64 GOOS=windows go1.20.14 build -trimpath -o bin/windows7/
