FROM python:3.6-alpine3.8

RUN apk -U --no-cache add git build-base && \
    rm -rf /root/* && \
    rm -rf /tmp/* /var/tmp/* && \
    rm -rf /var/cache/apk/*
RUN pip3 install --no-cache-dir -U pip setuptools
ADD requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

ADD . .
RUN python3 setup.py install

ENV PORT 80
ENV TANNER 172.17.0.1

RUN clone --target 0.0.0.0:8000

CMD snare --no-dorks true --auto-update false --port $PORT --page-dir "localhost" --tanner $TANNER
