# Define variables
$httpDeploymentFile = "$PSScriptRoot\http-deployment.yaml"
$ftpDeploymentFile = "$PSScriptRoot\ftp-deployment.yaml"
$rdpDeploymentFile = "$PSScriptRoot\rdp-deployment.yaml"
$httpServiceFile = "$PSScriptRoot\http-service.yaml"
$ftpServiceFile = "$PSScriptRoot\ftp-service.yaml"
$rdpServiceFile = "$PSScriptRoot\rdp-service.yaml"
$namespace = "myservices"  # Namespace for your services

# Step 1: Check and install kubectl if not already installed
if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Output "kubectl not found. Installing kubectl..."
    Invoke-WebRequest -Uri "https://dl.k8s.io/release/v1.22.0/bin/windows/amd64/kubectl.exe" -OutFile "$env:USERPROFILE\kubectl.exe"
    $env:Path += ";$env:USERPROFILE"
    Write-Output "kubectl installed."
} else {
    Write-Output "kubectl is already installed."
}

# Step 2: Create a namespace for the services
Write-Output "Creating namespace '$namespace'..."
kubectl create namespace $namespace

# Step 3: Define YAML configurations for HTTP, FTP, and RDP services

# HTTP Deployment YAML
$httpDeployment = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: http-service
  namespace: $namespace
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
"@
$httpDeployment | Out-File -FilePath $httpDeploymentFile

# FTP Deployment YAML
$ftpDeployment = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ftp-service
  namespace: $namespace
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
"@
$ftpDeployment | Out-File -FilePath $ftpDeploymentFile

# RDP Deployment YAML
$rdpDeployment = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rdp-service
  namespace: $namespace
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
"@
$rdpDeployment | Out-File -FilePath $rdpDeploymentFile

# HTTP Service YAML
$httpService = @"
apiVersion: v1
kind: Service
metadata:
  name: http-service
  namespace: $namespace
spec:
  selector:
    app: http
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
"@
$httpService | Out-File -FilePath $httpServiceFile

# FTP Service YAML
$ftpService = @"
apiVersion: v1
kind: Service
metadata:
  name: ftp-service
  namespace: $namespace
spec:
  selector:
    app: ftp
  ports:
  - protocol: TCP
    port: 21
    targetPort: 21
  type: LoadBalancer
"@
$ftpService | Out-File -FilePath $ftpServiceFile

# RDP Service YAML
$rdpService = @"
apiVersion: v1
kind: Service
metadata:
  name: rdp-service
  namespace: $namespace
spec:
  selector:
    app: rdp
  ports:
  - protocol: TCP
    port: 3389
    targetPort: 3389
  type: LoadBalancer
"@
$rdpService | Out-File -FilePath $rdpServiceFile

# Step 4: Deploy the services in Kubernetes
Write-Output "Applying deployments and services to Kubernetes cluster..."

kubectl apply -f $httpDeploymentFile
kubectl apply -f $ftpDeploymentFile
kubectl apply -f $rdpDeploymentFile
kubectl apply -f $httpServiceFile
kubectl apply -f $ftpServiceFile
kubectl apply -f $rdpServiceFile

Write-Output "Deployments and services have been successfully applied."
