# ========================================================================
# Diagnose Keycloak Authentication Issues
# ========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Keycloak Connection Diagnostic" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Step 1: Check if Keycloak is accessible from User Service
Write-Host ""
Write-Host "[1/5] Testing Keycloak accessibility from User Service pod..." -ForegroundColor Yellow

$userServicePod = kubectl get pods -n student-housing -l app=user-service-app -o jsonpath='{.items[0].metadata.name}'

if ($userServicePod) {
    Write-Host "User Service Pod: $userServicePod" -ForegroundColor White

    Write-Host ""
    Write-Host "Testing connection to Keycloak..." -ForegroundColor Gray
    kubectl exec -n student-housing $userServicePod -- curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://keycloak.student-housing.svc.cluster.local:8080/realms/friendly-housing

    Write-Host ""
    Write-Host "Testing JWK Set URI..." -ForegroundColor Gray
    kubectl exec -n student-housing $userServicePod -- curl -s http://keycloak.student-housing.svc.cluster.local:8080/realms/friendly-housing/protocol/openid-connect/certs | head -c 200
} else {
    Write-Host "User Service pod not found!" -ForegroundColor Red
}

# Step 2: Check User Service logs for errors
Write-Host ""
Write-Host ""
Write-Host "[2/5] Checking User Service logs for authentication errors..." -ForegroundColor Yellow
kubectl logs -n student-housing -l app=user-service-app --tail=50 | Select-String -Pattern "401|Unauthorized|OAuth|JWT|Keycloak|authentication" -Context 1,1

# Step 3: Verify ConfigMap settings
Write-Host ""
Write-Host "[3/5] Checking OAuth2 Configuration..." -ForegroundColor Yellow
kubectl get configmap user-service-config -n student-housing -o yaml | Select-String -Pattern "OAUTH2|KEYCLOAK|JWT"

# Step 4: Verify Secret
Write-Host ""
Write-Host "[4/5] Checking if client secret is set..." -ForegroundColor Yellow
$secretExists = kubectl get secret user-service-secret -n student-housing -o jsonpath='{.data.SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_SECRET}' 2>$null
if ($secretExists) {
    Write-Host "Client secret exists in Kubernetes secret" -ForegroundColor Green
} else {
    Write-Host "Client secret is MISSING!" -ForegroundColor Red
}

# Step 5: Check Keycloak client configuration
Write-Host ""
Write-Host "[5/5] Verification Steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Please verify in Keycloak (http://localhost:8080):" -ForegroundColor White
Write-Host "  1. Login as admin" -ForegroundColor Gray
Write-Host "  2. Select 'friendly-housing' realm" -ForegroundColor Gray
Write-Host "  3. Go to Clients > user-service" -ForegroundColor Gray
Write-Host "  4. Check the following:" -ForegroundColor Gray
Write-Host "     - Client authentication: ON" -ForegroundColor Gray
Write-Host "     - Authorization: OFF (unless you need it)" -ForegroundColor Gray
Write-Host "     - Valid redirect URIs: *" -ForegroundColor Gray
Write-Host "     - Service accounts roles: enabled" -ForegroundColor Gray
Write-Host "  5. Go to 'Credentials' tab" -ForegroundColor Gray
Write-Host "     - Copy the 'Client secret'" -ForegroundColor Gray
Write-Host ""
Write-Host "Your current secret in screenshot: FbtQ0WYg09MgcbhHFufNXWM3YmuscLJI" -ForegroundColor Cyan
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Quick Fix Commands" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "If the secret doesn't match, update it:" -ForegroundColor Yellow
Write-Host 'kubectl delete secret user-service-secret -n student-housing' -ForegroundColor Gray
Write-Host 'kubectl create secret generic user-service-secret -n student-housing \' -ForegroundColor Gray
Write-Host '  --from-literal=SPRING_DATASOURCE_PASSWORD="Server123@" \' -ForegroundColor Gray
Write-Host '  --from-literal=SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_SECRET="YOUR_NEW_SECRET"' -ForegroundColor Gray
Write-Host ""
Write-Host "Then restart User Service:" -ForegroundColor Yellow
Write-Host 'kubectl rollout restart deployment/user-service-app -n student-housing' -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Show full User Service logs?" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
$response = Read-Host "Press Y to view full logs, or any key to exit"

if ($response -eq "Y" -or $response -eq "y") {
    Write-Host ""
    Write-Host "Showing logs (press Ctrl+C to stop)..." -ForegroundColor Yellow
    kubectl logs -n student-housing -l app=user-service-app -f --tail=100
}