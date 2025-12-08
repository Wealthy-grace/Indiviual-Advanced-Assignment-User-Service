# PowerShell Deployment Script for User Service

Write-Host "=========================================="
Write-Host "User Service Cleanup and Deployment"
Write-Host "=========================================="
Write-Host ""

# Step 1: Delete test-curl pod
Write-Host "Step 1: Removing test-curl pod..." -ForegroundColor Yellow
kubectl delete pod test-curl -n student-housing --ignore-not-found=true
Write-Host "OK - test-curl pod removed" -ForegroundColor Green
Write-Host ""

# Step 2: Delete old user-service deployments
Write-Host "Step 2: Cleaning up old user-service deployments..." -ForegroundColor Yellow
kubectl delete deployment user-service-app -n student-housing --ignore-not-found=true
Write-Host "OK - Old deployments removed" -ForegroundColor Green
Write-Host ""

# Step 3: Wait for pods to terminate
Write-Host "Step 3: Waiting for old pods to terminate..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Write-Host "OK - Old pods terminated" -ForegroundColor Green
Write-Host ""

# Step 4: Apply the configuration
Write-Host "Step 4: Applying user-service configuration..." -ForegroundColor Yellow
kubectl apply -f K8s/user-service/user-service.yaml
Write-Host "OK - Configuration applied" -ForegroundColor Green
Write-Host ""

# Step 5: Wait for deployment to be ready
Write-Host "Step 5: Waiting for user-service to be ready (this may take 2-3 minutes)..." -ForegroundColor Yellow
kubectl wait --for=condition=available --timeout=300s deployment/user-service-app -n student-housing
Write-Host "OK - User service is ready!" -ForegroundColor Green
Write-Host ""

# Step 6: Check pod status
Write-Host "Step 6: Current pod status:" -ForegroundColor Cyan
kubectl get pods -n student-housing | Select-String "user-service"
Write-Host ""

# Step 7: Show service endpoints
Write-Host "Step 7: Service endpoints:" -ForegroundColor Cyan
kubectl get svc -n student-housing | Select-String "user-service"
Write-Host ""

Write-Host "=========================================="
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "=========================================="