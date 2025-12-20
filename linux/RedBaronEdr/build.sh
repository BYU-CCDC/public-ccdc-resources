# editing to make sure docker is installed first
if command -v docker >/dev/null 2>&1; then
    echo "Using existing installation..."
else
    # from https://github.com/docker/docker-install
    echo "Docker not found. Installing now..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
fi

# build for amd64 architecture
sudo docker build --platform linux/amd64 -t go-red .
sudo docker create --name go-red go-red
sudo docker cp go-red:/build/red .
sudo docker rm -f go-red
