FROM ubuntu:18.04

MAINTAINER Sebastien Macke <lanjelot@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y python3-dev git python3-pip

WORKDIR /opt/albatar
RUN git clone https://github.com/lanjelot/albatar/ .
RUN python3 -m pip install requests
