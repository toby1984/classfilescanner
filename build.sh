#!/bin/bash
echo "Building linux-amd64 ..."
GOOS=linux GOARCH=amd64 go build -o classfilescanner-linux-amd64
echo "Building linux-arm64 ..."
GOOS=linux GOARCH=arm64 go build -o classfilescanner-linux-arm64
echo "Building windows-amd64 ..."
GOOS=windows GOARCH=amd64 go build -o classfilescanner-windows-arm64
echo "Building windows-arm64 ..."
GOOS=windows GOARCH=arm64 go build -o classfilescanner-windows-arm64
echo "Building darwin-amd64 ..."
GOOS=darwin GOARCH=amd64 go build -o classfilescanner-darwin-amd64
echo "Building darwin-arm64 ..."
GOOS=darwin GOARCH=arm64 go build -o classfilescanner-darwin-arm64
