#! /bin/bash

if [ ! -d scripts/ ]
then
  printf "Please run script from project root directory."
  exit
fi

go mod download
go run AutomotiveCpsServer.go
