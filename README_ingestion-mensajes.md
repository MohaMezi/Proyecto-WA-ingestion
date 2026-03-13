# Lambda Ingestion Mensajes

## Descripción
Recibe webhooks de Meta (WhatsApp, Messenger e Instagram), valida firma, aplica controles de seguridad/flujo (deduplicacion, rate limiting y bloqueos), persiste mensajes en DynamoDB y encola procesamiento asincrono en SQS. Tambien resuelve la verificacion GET del webhook.

## Trigger
API Gateway HTTP API:
- `GET /ingestion_mensajes/dev` para verificacion del webhook (`hub.challenge`).
- `POST /ingestion_mensajes/dev` para eventos de mensajes entrantes desde Meta.

## Variables de Entorno
| Variable | Requerida | Descripcion | Ejemplo |
|----------|-----------|-------------|---------|
| `ENV` | Si | Prefijo de entorno para rutas SSM y tablas. | `dev` |
| `WEBHOOK_PATH` | Si | Ruta exacta esperada del endpoint del webhook. | `/ingestion_mensajes/dev` |
| `DYNAMODB_TABLE_PREFIX` | Si | Prefijo de tablas DynamoDB (`<prefix>-conversations`, `-deduplication`, `-channels`, `-tenants`). | `dev` |
| `QUEUE_URL` | Si | URL de cola SQS para encolar mensajes a procesado. | `https://sqs.eu-south-2.amazonaws.com/185271206346/dev-mensajes` |
| `LOG_LEVEL` | No | Nivel de logging. | `INFO` |
| `GRAPH_VERSION` | No | Version de Meta Graph API para respuestas salientes. | `v22.0` |
| `CACHE_TTL_SECONDS` | No | TTL de cache en memoria para SSM/channels/tenants. | `300` |
| `DEDUP_TTL_HOURS` | No | TTL de registros deduplicados en DynamoDB. | `72` |
| `HTTP_REQUEST_TIMEOUT_SECONDS` | No | Timeout HTTP para llamadas a Meta Graph API. | `10` |
| `ACTIVE_SERVICE_STATUS` | No | Valor considerado como tenant activo. | `active` |
| `INACTIVE_SERVICE_MESSAGE` | No | Mensaje fallback cuando el tenant no esta activo. | `El servicio no esta disponible temporalmente...` |
| `SQS_DELAY_SECONDS` | No | Delay al enviar mensaje a SQS. | `10` |

## Permisos IAM Requeridos
- `ssm:GetParameter` sobre:
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/meta_verify_token`
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/app_secret/*`
  - `arn:aws:ssm:<region>:<account-id>:parameter/<ENV>/access_token/*`
- `dynamodb:TransactWriteItems` sobre tablas `*-deduplication` y `*-conversations`.
- `dynamodb:GetItem` sobre tablas `*-conversations`, `*-channels`, `*-tenants`.
- `dynamodb:UpdateItem` sobre tablas `*-conversations` y `*-channels`.
- `sqs:SendMessage` sobre la cola configurada en `QUEUE_URL`.
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` sobre `/aws/lambda/<function-name>` (`⚠️ *inferido*`).

## Input
Evento de API Gateway v2.

```json
{
  "version": "2.0",
  "rawPath": "/ingestion_mensajes/dev",
  "rawQueryString": "hub.mode=subscribe&hub.verify_token=TOKEN&hub.challenge=123",
  "headers": {
    "x-hub-signature-256": "sha256=<firma>",
    "content-type": "application/json"
  },
  "requestContext": {
    "http": {
      "method": "POST",
      "path": "/ingestion_mensajes/dev"
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
| `400 Bad Request` | Body JSON invalido, `channel_id`/`message_id`/`sender_id` no extraibles, mensaje vacio. | Validar formato del webhook segun canal. |
| `500 Internal Server Error` | Fallos DynamoDB/SSM/SQS/Meta Graph no recuperables. | Revisar CloudWatch logs, permisos IAM y disponibilidad de servicios externos. |
| `ClientError: ConditionalCheckFailedException` | Mensaje duplicado en tabla de deduplicacion. | Comportamiento esperado (idempotencia): se responde `200 OK`. |

## Despliegue
```bash
# 1) Construir imagen
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
docker build -t wa-ingestion .
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

## Notas
- ⚠️ `get_channel_info` y `get_tenant_info` usan `dynamodb.meta.client.get_item` (formato AttributeValue), pero en varias partes se consumen como si fueran valores planos. Esto puede romper extraccion de `tenant_id` y comparaciones como `service_status == active`.
- ⚠️ Si `service_status` llega en formato `{"S":"active"}`, la funcion puede entrar siempre por ruta de "tenant inactivo" y responder al usuario sin encolar procesamiento.
- ⚠️ La lista `message_times` crece indefinidamente (no hay poda). Puede aumentar costo/tamano del item en conversaciones de alto trafico.
- La funcion implementa deduplicacion idempotente por `(channel_id, message_id)` en transaccion con persistencia de conversacion.
- No hay reintento explicito de llamadas `requests` hacia Meta; la resiliencia depende de retries de invocacion aguas arriba.
