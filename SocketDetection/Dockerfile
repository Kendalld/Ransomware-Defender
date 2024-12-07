FROM ubuntu:latest
WORKDIR /app
EXPOSE 5001
COPY . /app
RUN apt update
RUN apt install -y sudo
RUN apt-get -y install bsdmainutils
RUN apt -y install make
RUN apt install -y build-essential
RUN apt -y install strace
RUN make -d
RUN ["chmod", "+x", "./ransomTrace.sh"]
#CMD ["bash", "ransomTrace.sh"]
CMD ["sleep", "infinity"]