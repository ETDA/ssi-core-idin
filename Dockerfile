FROM golang:1.16.4-alpine3.13

RUN apk update && apk upgrade && \
apk add --no-cache bash git openssh
RUN apk add build-base
RUN git config --global url."https://core-deploy:a4NaMfxHGhtfEtuGSuKX@ssi-gitlab.teda.th".insteadOf "https://ssi-gitlab.teda.th"
RUN go get -u github.com/pilu/fresh

WORKDIR /app
