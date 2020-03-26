FROM golang:1.14-buster

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list &&\
    echo "deb [signed-by=/usr/share/keyrings/adoptopenjdk.gpg] https://adoptopenjdk.jfrog.io/adoptopenjdk/deb buster main" | tee -a /etc/apt/sources.list.d/adoptopenjdk.list &&\
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - &&\
    curl https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | apt-key --keyring /usr/share/keyrings/adoptopenjdk.gpg add - &&\
    apt-get update -y &&\
    apt-get install -y adoptopenjdk-11-hotspot google-cloud-sdk &&\
    # work around broken dependency on openjdk-8-jdk
    cd /tmp &&\
    apt-get download google-cloud-sdk-datastore-emulator &&\
    dpkg -i --ignore-depends=openjdk-8-jdk google-cloud-sdk-datastore-emulator*.deb

ADD go.mod go.sum /app/
RUN cd /app && go mod download

ADD . /app

WORKDIR /app
ENTRYPOINT ["/app/script/test.sh"]
