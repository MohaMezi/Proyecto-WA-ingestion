# deploy.ps1
param(
    [Parameter(Mandatory)][string]$LambdaName,
    [Parameter(Mandatory)][string]$Namespace,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Message
)

$ErrorActionPreference = "Stop"

$AWS_ACCOUNT = "185271206346"
$REGION = "eu-south-2"
$ECR_URI = "${AWS_ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${Namespace}:${LambdaName}"

Write-Host "🚀 Desplegando $LambdaName v$Version..."

git add .
git commit -m "Version ${Version}: ${Message}"
git push -u origin master

docker build --provenance=false -t "${Namespace}:${LambdaName}" .
docker tag "${Namespace}:${LambdaName}" $ECR_URI
docker push $ECR_URI

aws lambda update-function-code `
    --function-name $LambdaName `
    --region $REGION `
    --image-uri $ECR_URI

Write-Host "✅ $LambdaName desplegada correctamente."