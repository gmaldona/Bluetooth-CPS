FROM golang:latest AS build

WORKDIR /release

COPY . .

RUN chmod +x ./scripts/build.sh

ENTRYPOINT ["./scripts/build.sh"]
