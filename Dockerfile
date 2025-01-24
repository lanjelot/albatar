FROM python:3-alpine

RUN apk add --no-cache libcurl

# for pycurl
ENV PYCURL_SSL_LIBRARY=openssl

RUN apk add --no-cache --virtual .build-deps build-base curl-dev \
  && python3 -m ensurepip --upgrade \
  && pip install -U requests pycurl \
  && apk del --purge .build-deps

WORKDIR /opt/albatar
ENTRYPOINT ["python3"]

# usage:
# docker build -t albatar .
# docker run --rm -it -v $PWD:/opt/albatar --add-host=host.docker.internal:host-gateway albatar poc.py -h
