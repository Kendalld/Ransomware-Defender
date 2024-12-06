FROM ubuntu:latest
WORKDIR /app
EXPOSE 5001
COPY . /app
RUN apt update
RUN apt-get -y install bsdmainutils
RUN apt -y install make
RUN apt install -y build-essential
RUN make -d
#CMD ["./SocketEncrypt"]
CMD ["sleep", "infinity"]