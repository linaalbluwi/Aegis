Multi-Region Deployment

Architecture
Region A (Primary): eu-west-1 or me-central-1
Region B (Failover): eu-central-1 or me-south-1

Deployment
kubectl config use-context region-a
kubectl apply -f k8s/

kubectl config use-context region-b
kubectl apply -f k8s/

DNS Failover
Health check endpoint: /health
Protocol: HTTPS
Port: 443
Interval: 30 seconds
Failure threshold: 3 consecutive failures
TTL: 60 seconds
