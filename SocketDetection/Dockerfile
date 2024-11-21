FROM ubuntu:latest
WORKDIR /usr/src/app 
EXPOSE 5001
COPY . .
RUN apt-get update
RUN apt-get install upgrade
RUN make
CMD ["./SocketEncrypt"]