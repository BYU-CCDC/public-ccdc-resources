#!/bin/bash

# Define variables
NAMESPACE="myservices"
HTTP_DEPLOYMENT="http-deployment.yaml"
FTP_DEPLOYMENT="ftp-deployment.yaml"
RDP_DEPLOYMENT="rdp-deployment.yaml"
HTTP_SERVICE="http-service.yaml"
FTP_SERVICE="ftp-service.yaml"
RDP_SERVICE="rdp-service.yaml"

# Function to log events
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Step 1: Check and install kubectl if not already installed
if ! command -v kubectl &> /dev/null; then
    log "kubectl not found. Installing kubectl..."
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/
    log "kubectl installed."
else
    log "kubectl is already installed."
fi

# Step 2: Create a namespace for the services
log "Creating namespace '$NAMESPACE'..."
kubectl create namespace $NAMESPACE || log "Namespace '$NAMESPACE' already exists."

# Step 3: Define YAML configurations for HTTP, FTP, and RDP services

# HTTP Deployment YAML
cat <<EOF > $HTTP_DEPLOYMENT
apiVersion: apps/v1
kind: Deployment
metadata:
  name: http-service
  namespace: $NAMESPACE
spec:
  replicas: 2
  selector:
    matchLabels:
      app: http
  template:
    metadata:
      labels:
        app: http
    spec:
      containers:
      - name: http-container
        image: httpd:latest
        ports:
        - containerPort: 80
EOF

# FTP Deployment YAML
cat <<EOF > $FTP_DEPLOYMENT
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ftp-service
  namespace: $NAMESPACE
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ftp
  template:
    metadata:
      labels:
        app: ftp
    spec:
      containers:
      - name: ftp-container
        image: fauria/vsftpd
        ports:
        - containerPort: 21
EOF

# RDP Deployment YAML
cat <<EOF > $RDP_DEPLOYMENT
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rdp-service
  namespace: $NAMESPACE
spec:
  replicas: 2
  selector:
    matchLabels:
      app: rdp
  template:
    metadata:
      labels:
        app: rdp
    spec:
      containers:
      - name: rdp-container
        image: oznu/xrdp
        ports:
        - containerPort: 3389
EOF

# HTTP Service YAML
cat <<EOF > $HTTP_SERVICE
apiVersion: v1
kind: Service
metadata:
  name: http-service
  namespace: $NAMESPACE
spec:
  selector:
    app: http
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
EOF

# FTP Service YAML
cat <<EOF > $FTP_SERVICE
apiVersion: v1
kind: Service
metadata:
  name: ftp-service
  namespace: $NAMESPACE
spec:
  selector:
    app: ftp
  ports:
  - protocol: TCP
    port: 21
    targetPort: 21
  type: LoadBalancer
EOF

# RDP Service YAML
cat <<EOF > $RDP_SERVICE
apiVersion: v1
kind: Service
metadata:
  name: rdp-service
  namespace: $NAMESPACE
spec:
  selector:
    app: rdp
  ports:
  - protocol: TCP
    port: 3389
    targetPort: 3389
  type: LoadBalancer
EOF

# Step 4: Deploy the services in Kubernetes
log "Applying deployments and services to Kubernetes cluster..."

kubectl apply -f $HTTP_DEPLOYMENT
kubectl apply -f $FTP_DEPLOYMENT
kubectl apply -f $RDP_DEPLOYMENT
kubectl apply -f $HTTP_SERVICE
kubectl apply -f $FTP_SERVICE
kubectl apply -f $RDP_SERVICE

log "Deployments and services have been successfully applied."

# Step 5: Clean up YAML files (optional)
rm $HTTP_DEPLOYMENT $FTP_DEPLOYMENT $RDP_DEPLOYMENT $HTTP_SERVICE $FTP_SERVICE $RDP_SERVICE
log "Temporary YAML files have been removed."
