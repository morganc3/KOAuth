#!/bin/zsh 
GOOS=linux GOARCH=amd64 go build
docker run --rm -it -v "$(pwd):/host" -p 80:8000 -w /host gcr.io/praetorian-engineering/ubuntu-tools:latest /host/KOAuth