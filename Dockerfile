FROM metascan/alpine-sslv3:latest
LABEL maintainer="maurosoria@protonmail.com"

WORKDIR /root/
ADD . /root/

RUN apk add --no-cache \
    python3 \
    py3-pip \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    libffi-dev

RUN ln -sf /usr/bin/python3 /usr/bin/python

RUN python3 -m pip install --no-cache-dir -r requirements.txt
RUN chmod +x dirsearch.py

ENTRYPOINT ["./dirsearch.py"]
CMD ["--help"]
