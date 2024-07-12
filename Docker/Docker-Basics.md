# Docker Basics

# Install

```bash
sudo apt install docker-compose
```
## Usage
it uses a file named `Dockerfile` which contains the script to run to containerize the targeted app  

1. Create the `Dockerfile` at the app's root directory
```bash
touch Dockerfile
```

2. Copy and past in
```Dockerfile
FROM node:18-alpine

WORKDIR /app
COPY . .
RUN yarn install --production
CMD ["node", "src/index.js"]
EXPOSE 3000
```

- Start from the node:18-alpine image
- WORKDIR /directory_to_build
- The CMD directive specifies the default command to run when starting a container from this image.
- EXPOSE port

3. Build the docker and generate yarn.lock
```bash
sudo docker build -t getting-started .
```
- `getting-started` is the output name
- `.` means that the Dockerfile is in the current directory


4. Run the docker
```bash
sudo docker run -dp 8080:80 getting-started
```
- `-d` is used to run the docker in the background
- `-p` is used to create a mapping between local port and docker port
- `getting-started` is the docker name
- `8080` local port
- `80` docker exposed port
5. Wait a second 

# Tips

- Using `tail -f filename.txt` as the `CMD` value in `Dockerfile` will get the docker never end 

# Command Cheat sheet

```bash
sudo docker ps # list running dockers
sudo docker stop DOCKER_ID 
sudo docker rm DOCKER_ID
sudo docker rm -f DOCKER_ID # force remove
sudo docker image ls # list dockers
sudo docker exec -it DOCKER_PS_ID /bin/bash # Get into the docker's shell
```

# Cleanup

```bash
docker system prune # Remove all unused data
docker swarm leave --force # leave the swarm env
docker service rm $(docker service ls -q) # Remove all services
docker stop $(docker ps -aq) --force # Remove all containers
docker rmi $(docker images -q) --force
```

## Share the app
1. On the web app
	1. Login to https://hub.docker.com/
	2. Select the Create Repository button
	3. Type the repo name and make sure the visibility is Public
	4. Select the Create button.
2. With command lines
	1. sudo docker login -u USERNAME
	2. sudo docker tag DOCKER_NAME USERNAME/TAG # Give the docker a tag
	3. docker push YOUR-USER-NAME/TAG



