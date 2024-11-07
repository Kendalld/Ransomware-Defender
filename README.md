###### ** Note This README is still being edited

## How to Setup Containerized enviroment

To setup build the container do the following:
-   run command `docker build -t victimserver .`. This will be used to build the docker image.  
-   run command `docker run -d -p 8000:5001 victimserver`.8000 is the port open to the container on the host while 5001 is open port on the container.
-   The container should be running, you can now access send a request to the image to confirm.

To simulate attack and a victim run command `docker compose up -d`