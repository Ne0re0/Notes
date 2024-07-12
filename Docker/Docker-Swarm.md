# Docker-Swarm

- Docker-Swarm is a service which allows users to create and manage a cluster of Docker nodes and schedule containers.

### Features

- Decentralized
- High security
-  Auto-Load balancing
- High scalability
- Roll-back task

### Organization
- Containers are launched using services
- A service is a group of containers of the same image
- Services enable to scale your application
- You must have at least one node deployed
- There are two types of nodes
	- The manager node
		- control and manage tasks
	- Worker node
		- execute the instructions

**Manager node knows all workers status**
![](../images/Pasted%20image%2020240710103613.png)

**Workers nodes communicate with the manager using REST API**

# Example
**Requirements :**
- One manager VM
- One worker VM

**Init the manager**
`manager`
```bash
sudo docker swarm init
```

This command will generate a token to join a docker worker to the environnement

**Init the worker**
- Copy and paste the manager initialization output

`worker`
```bash
sudo docker swarm join --token TOKEN_HERE 192.168.2.151:2337
```

**List swarm nodes**
`manager`
```bash
sudo docker node ls
```

**Create a service**
`manager`
```bash
sudo docker service create --name servicename --mode global --replicas NumberOfReplicas ImageName CommandToRun
# Example :
sudo docker service create --name helloworld  --mode global  --replicas 1 alpine ping docker.com
```
**Note :** 
- It creates the service and start docker instance based on the mode

| Mode       | Meaning                                           |
| ---------- | ------------------------------------------------- |
| local      | Start a docker instance on the local machine only |
| global     | Starts a docker instance on each swarm node       |
| replicated |                                                   |


**List services**
`worker`
```bash
sudo docker service ls
```

**Remove a service**
`manager`
```bash
sudo docker service rm ServiceName
```
**Note :** It will automatically stop all running docker containers.

**Scale dockers**
`manager`
```bash
sudo docker service scale serviceName=workerNumber
# Example
sudo docker service scale helloworld=3
```
**Note :** Only works if the service is in `replicated` mode

**Remove a worker from swarm environnement**
`worker`
```bash
sudo docker swarm leave --force
```


# Stack

**When dealing with a `docker-compose.yml`, you will deal with a swarm stack**

### Update the `docker-compose.yml`

1. Add the `image:` tag and set the value to `127.0.0.1:5000`
2. If you want to set a wlan IP address, you can but you have to complete `/etc/docker/daemon.json` file with
```json
{ "insecure-registries": ["IP_ADDRESS:5000"] }
```

3. If `/etc/docker/daemon.json` has been updated, you have to restart the docker daemon
```bash
sudo systemctl restart docker
```

### Deploy a local registry

**Create the registry**
`manager`
```bash
sudo docker service create --name registry --publish published=5000,target=5000 registry:2
```

**Verify the creation**
`manager`
```bash
sudo docker service ls
curl http://localhost:5000/v2/ # should return {}
```
**Note :** It should be running on port 5000

### Deploy the app

**Test**
`manager`
```bash
sudo docker-compose up -d
# Test the app
sudo docker-compose down --volumes
```

### Deploy the app to a docker swarm

**Push the image on our local registry**
```bash
sudo docker-compose push
```
**Create the stack**
```bash
sudo docker stack deploy -c docker-compose.yml stackname
```

**Notice that** :
- There is one `docker-compose.yml` file used to build the image
- There is one `docker-compose-stack.yml` file used to build the stack
	- This is because the stack does not handle builds and requires an image

**List stack**
```bash
sudo docker stack ls
```

**Get stack status**
```bash
sudo docker stack ps stackname
```

**Scale the stack**
```bash
sudo docker service scale stackname=NBWorkers
```

# Be careful with volumes

**A docker always expects a volume to be present in the host filesystem**
Instead of duplicating data, it is possible to limit the containers in the `manager` node

```yaml
deploy:
    placement:
        constraints:
            - node.role == manager
```

# `docker-compose.yml`

```YAML
version: '3.8'

services:
  bind:
    image: 192.168.224.208:5000/dns-rpz
    build: .
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "22:22"
    volumes:
      - ./zones/db.rpz:/zones/db.rpz:ro
      - ./logs/:/var/log/named/
    cap_add:
      - NET_ADMIN
    deploy:
      placement:
        constraints:
          - node.role == manager // limitation because of volumes being only present on the manager node
```

