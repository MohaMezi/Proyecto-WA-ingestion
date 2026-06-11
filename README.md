# Lambda Ingestion Mensajes

## Descripción
Recibe webhooks de Meta (WhatsApp, Messenger e Instagram), valida firma HMAC SHA-256, aplica controles de seguridad/flujo (deduplicacion idempotente, rate limiting con bloqueo de usuarios y descarte de mensajes demasiado largos), persiste mensajes en DynamoDB y encola procesamiento asincrono en SQS. Tambien resuelve la verificacion GET del webhook y responde directamente al usuario cuando el tenant esta inactivo.

## Trigger
API Gateway HTTP API (la ruta exacta la define `WEBHOOK_PATH`):
- `GET <WEBHOOK_PATH>` para verificacion del webhook (`hub.challenge`).
- `POST <WEBHOOK_PATH>` para eventos de mensajes entrantes desde Meta.

## Variables de Entorno
| Variable | Requerida | Descripcion | Ejemplo |
|----------|-----------|-------------|---------|
| `ENV` | Si | Prefijo de entorno para rutas SSM y tablas. | `dev` |
| `WEBHOOK_PATH` | Si | Ruta exacta esperada del endpoint del webhook. | `/lambda-ingesta` |
| `DYNAMODB_TABLE_PREFIX` | Si | Prefijo de tablas DynamoDB (`<prefix>-conversations`, `-deduplication`, `-channels`, `-tenants`). | `dev` |
| `QUEUE_URL` | Si | URL de cola SQS para encolar mensajes a procesado. | `https://sqs.<region>.amazonaws.com/<account-id>/dev-mensajes` |
| `LOG_LEVEL` | No | Nivel de logging. | `INFO` |
| `GRAPH_VERSION` | No | Version de Meta Graph API para respuestas salientes. | `v22.0` |
| `CACHE_TTL_SECONDS` | No | TTL de cache en memoria para SSM/channels/tenants. | `300` |
| `DEDUP_TTL_HOURS` | No | TTL de registros deduplicados en DynamoDB. | `72` |
| `HTTP_REQUEST_TIMEOUT_SECONDS` | No | Timeout HTTP para llamadas a Meta Graph API. | `10` |
| `ACTIVE_SERVICE_STATUS` | No | Valor considerado como tenant activo. | `active` |
| `INACTIVE_SERVICE_MESSAGE` | No | Mensaje fallback cuando el tenant no esta activo. | `El servicio no esta disponible temporalmente...` |
| `SQS_DELAY_SECONDS` | No | Delay al enviar mensaje a SQS. | `10` |
| `TOO_LONG_MESSAGE_THRESHOLD` | No | Caracteres a partir de los cuales el mensaje se considera demasiado largo y se descarta. | `1000` |
| `TOO_LONG_MESSAGE_RESPONSE` | No | Respuesta enviada al usuario cuando el mensaje es demasiado largo. | `El mensaje que has enviado es demasiado largo...` |
| `TOO_MANY_MESSAGES_THRESHOLD` | No | Numero de mensajes recientes que dispara el bloqueo del usuario (rate limiting). | `20` |
| `TOO_MANY_MESSAGES_TIME_SECONDS` | No | Ventana en segundos para contar mensajes recientes en el rate limiting. | `2` |

## Permisos IAM Requeridos
- `ssm:GetParameter` sobre:
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/meta_verify_token`
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/app_secret/*`
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/access_token/*`
- `dynamodb:PutItem` y `dynamodb:DeleteItem` sobre tabla `*-deduplication` (alta idempotente y rollback).
- `dynamodb:GetItem` sobre tablas `*-conversations`, `*-channels`, `*-tenants`.
- `dynamodb:UpdateItem` sobre tablas `*-conversations` y `*-channels` (estado, encolado y `blocked_users`).
- `sqs:SendMessage` sobre la cola configurada en `QUEUE_URL`.
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` sobre `/aws/lambda/<function-name>` (`⚠️ *inferido*`).

## Input
Evento de API Gateway v2.

```json
{
  "version": "2.0",
  "rawPath": "/lambda-ingesta",
  "rawQueryString": "hub.mode=subscribe&hub.verify_token=TOKEN&hub.challenge=123",
  "headers": {
    "x-hub-signature-256": "sha256=<firma>",
    "content-type": "application/json"
  },
  "requestContext": {
    "http": {
      "method": "POST",
      "path": "/lambda-ingesta"
    }
  },
  "isBase64Encoded": false,
  "body": "{\"object\":\"whatsapp_business_account\",\"entry\":[{\"changes\":[{\"value\":{\"metadata\":{\"phone_number_id\":\"123\"},\"messages\":[{\"id\":\"wamid.123\",\"from\":\"34123456789\",\"text\":{\"body\":\"hola\"}}]}}]}]}"
}
```

## Output
Respuesta HTTP compatible con API Gateway.

```json
{
  "statusCode": 200,
  "body": "OK"
}
```

Tambien puede devolver `400`, `403`, `404`, `405` o `500` segun validaciones y errores.

## Dependencias
- AWS DynamoDB (`<prefix>-conversations`, `<prefix>-deduplication`, `<prefix>-channels`, `<prefix>-tenants`).
- AWS SQS (cola de mensajes de procesado).
- AWS Systems Manager Parameter Store (tokens/secrets).
- Meta Graph API (`/me/messages`, `/{phone_number_id}/messages`).
- API Gateway HTTP API.

## Errores Comunes
| Código/Tipo | Causa | Solución |
|-------------|-------|----------|
| `404 Not Found` | `rawPath` no coincide con `WEBHOOK_PATH`. | Ajustar ruta en API Gateway o variable `WEBHOOK_PATH`. |
| `403 Forbidden` | Firma `x-hub-signature-256` invalida o token de verificacion incorrecto. | Verificar `app_secret`/`meta_verify_token` en SSM y firma enviada por Meta. |
| `400 Bad Request` | Body JSON invalido, `channel_id`/`message_id`/`sender_id` no extraibles, `tenant_id` no resuelto o mensaje vacio. | Validar formato del webhook segun canal y registro del canal en DynamoDB. |
| `500 Internal Server Error` | Fallos DynamoDB/SSM/SQS/Meta Graph no recuperables o error al obtener el `meta_verify_token`. | Revisar CloudWatch logs, permisos IAM y disponibilidad de servicios externos. |
| `200 OK` (sin encolar) | Mensaje duplicado, usuario bloqueado, rate limit superado, mensaje demasiado largo o tenant inactivo. | Comportamiento esperado: el mensaje no se procesa (idempotencia/seguridad/flujo). |

## Despliegue
```bash
# 1) Construir imagen
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
docker build --provenance=false -t wa-ingestion .
docker tag wa-ingestion:latest <account-id>.dkr.ecr.<region>.amazonaws.com/wa-ingestion:latest
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/wa-ingestion:latest

# 2) Actualizar Lambda basada en contenedor
aws lambda update-function-code \
  --function-name <lambda-ingestion-name> \
  --image-uri <account-id>.dkr.ecr.<region>.amazonaws.com/wa-ingestion:latest

# 3) Actualizar variables de entorno (ejemplo)
aws lambda update-function-configuration \
  --function-name <lambda-ingestion-name> \
  --environment file://env.dev.json
```