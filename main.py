'''
WEBHOOK POST WHATSAPP:

{
  "object": "whatsapp_business_account",
  "entry": [
    {
      "id": "WABA_ID",
      "changes": [
        {
          "field": "messages",
          "value": {
            "messaging_product": "whatsapp",
            "metadata": {
              "display_phone_number": "PHONE_NUMBER",
              "phone_number_id": "PHONE_NUMBER_ID"
            },
            "contacts": [
              {
                "profile": { "name": "USER_NAME" },
                "wa_id": "USER_WA_ID"
              }
            ],
            "messages": [
              {
                "from": "USER_WA_ID",
                "id": "MESSAGE_ID",
                "timestamp": "TIMESTAMP",
                "type": "text",
                "text": { "body": "MESSAGE_BODY" }
              }
            ],
            "statuses": [
              {
                "id": "MESSAGE_ID",
                "status": "delivered|read|sent|failed",
                "timestamp": "TIMESTAMP",
                "recipient_id": "USER_WA_ID"
              }
            ]
          }
        }
      ]
    }
  ]
}
'''

'''
WEBHOOK POST MESSENGER/INSTAGRAM:

{
  "object": "page/instagram",
  "entry": [
    {
      "id": "PAGE_ID",
      "time": 1234567890,
      "messaging": [
        {
          "sender": { "id": "USER_PSID" },
          "recipient": { "id": "PAGE_ID" },
          "timestamp": 1234567890,
          "message": {
            "mid": "MESSAGE_ID",
            "text": "MESSAGE_BODY"
          }
        }
      ]
    }
  ]
}
'''

'''
API GATEWAY EVENT:

{
  version: '2.0',
  routeKey: '$default',
  rawPath: '/my/path',
  rawQueryString: 'parameter1=value1&parameter1=value2&parameter2=value',
  cookies: [ 'cookie1', 'cookie2' ],
  headers: {
    'Header1': 'value1',
    'Header2': 'value2'
  },
  queryStringParameters: { parameter1: 'value1,value2', parameter2: 'value' },
  requestContext: {
    accountId: '123456789012',
    apiId: 'api-id',
    authorizer: { jwt: {
        claims: {'claim1': 'value1', 'claim2': 'value2'},
        scopes: ['scope1', 'scope2']
        }
    },
    domainName: 'id.execute-api.us-east-1.amazonaws.com',
    domainPrefix: 'id',
    http: {
      method: 'POST',
      path: '/my/path',
      protocol: 'HTTP/1.1',
      sourceIp: 'IP',
      userAgent: 'agent'
    },
    requestId: 'id',
    routeKey: '$default',
    stage: '$default',
    time: '12/Mar/2020:19:03:58 +0000',
    timeEpoch: 1583348638390
  },
  body: 'Hello from Lambda',
  pathParameters: {'parameter1': 'value1'},
  isBase64Encoded: false,
  stageVariables: {'stageVariable1': 'value1', 'stageVariable2': 'value2'}
}
'''

'''
WEBHOOK GET VERIFICATION:

{
  "version": "2.0",
  "routeKey": "GET /webhook",
  "rawPath": "/webhook",
  "rawQueryString": "hub.mode=subscribe&hub.verify_token=TOKEN&hub.challenge=123",
  "headers": {
    "host": "...",
    "user-agent": "facebookexternalhit/..."
  },
  "requestContext": {
    "http": {
      "method": "GET",
      "path": "/webhook",
      "sourceIp": "..."
    }
  },
  "isBase64Encoded": false
}
'''

'''PARÁMETRO EN AWS SYSTEMS MANAGER PARAMETER STORE:

{
  "ARN": "arn:aws:ssm:region:acct:parameter/nombre-del-parámetro",
  "Name": "nombre-del-parámetro",
  "Type": "String|StringList|SecureString",
  "Value": "valor_del_parámetro",
  "Version": 1,
  "Selector": "",
  "DataType": "text",
  "LastModifiedDate": datetime(...)
}
'''

# Librería para parsear query strings.
from time import time
from urllib.parse import parse_qs

# Librerías para verificar la firma del webhook.
import hmac
import hashlib

import base64 # Librería para codificar/decodificar en base64.

# Librerías para interactuar con AWS.
import boto3
from botocore.exceptions import ClientError

# Librerías para hacer logging estructurado y poder filtrar logs en CloudWatch.
import logging
import json

import os # Librería para manejar variables de entorno.
from typing import Any # Para anotaciones de tipos genéricos (por ejemplo, dict[str, Any]).

import requests # Librería para hacer peticiones HTTP (en caso de querer enviar respuestas a los usuarios).

# ========== CONFIGURACIÓN DE PARÁMETROS AJUSTABLES ==========
_ENV = os.environ.get("ENV", "dev") # Variable de entorno para diferenciar entre entornos (dev, prod).
_GRAPH_VERSION = os.environ.get("GRAPH_VERSION", "v22.0") # Versión de la API de Meta Graph que se usará para enviar respuestas. Se puede actualizar según la versión más reciente disponible.
_CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", 300))  # 5 min  --  TTL para los parámetros cacheados (en segundos).
_DEDUP_TTL_HOURS = int(os.environ.get("DEDUP_TTL_HOURS", 72))  # TTL en horas para registros de deduplicación en DynamoDB.
_HTTP_REQUEST_TIMEOUT_SECONDS = int(os.environ.get("HTTP_REQUEST_TIMEOUT_SECONDS", 10))  # Timeout para peticiones HTTP a Meta Graph API.
_WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", f"/webhook/{_ENV}")  # Path del endpoint webhook esperado.
_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")  # Nivel de logging (DEBUG, INFO, WARNING, ERROR).
_ACTIVE_SERVICE_STATUS = os.environ.get("ACTIVE_SERVICE_STATUS", "active")  # Valor que indica que el servicio del tenant está activo.
_INACTIVE_SERVICE_MESSAGE = os.environ.get("INACTIVE_SERVICE_MESSAGE", "El servicio no está disponible temporalmente. Por favor, inténtalo de nuevo más tarde.")  # Mensaje por defecto cuando el servicio no está activo.
_TOO_LONG_MESSAGE_THRESHOLD = int(os.environ.get("TOO_LONG_MESSAGE_THRESHOLD", 1000))  # Número de caracteres a partir del cual se considera que un mensaje es "demasiado largo" para procesar normalmente.
_TOO_LONG_MESSAGE_RESPONSE = os.environ.get("TOO_LONG_MESSAGE_RESPONSE", "El mensaje que has enviado es demasiado largo para ser procesado. Por favor, envía un mensaje más corto.")  # Respuesta enviada al usuario cuando el mensaje es demasiado largo.
_TOO_MANY_MESSAGES_THRESHOLD = int(os.environ.get("TOO_MANY_MESSAGES_THRESHOLD", 20))  # Número de mensajes pendientes a partir del cual se considera que hay "demasiados mensajes pendientes" para procesar normalmente.
_TOO_MANY_MESSAGES_TIME_SECONDS = int(os.environ.get("TOO_MANY_MESSAGES_TIME_SECONDS", 2))  # Número de segundos en los que se cuentan los mensajes pendientes para determinar si hay "demasiados mensajes pendientes".
_DYNAMODB_TABLE_PREFIX = os.environ.get("DYNAMODB_TABLE_PREFIX", _ENV)  # Prefijo para nombres de tablas DynamoDB.
_QUEUE_URL = os.environ.get("QUEUE_URL", "")  # URL de la cola de SQS a la que se enviarán los mensajes para procesamiento asíncrono.
_SQS_DELAY_SECONDS = int(os.environ.get("SQS_DELAY_SECONDS", 10))  # Número de segundos de delay al enviar mensajes a SQS.

sm = boto3.client("ssm") # Cliente de AWS Systems Manager Parameter Store.
dynamodb = boto3.resource("dynamodb") # Recurso de DynamoDB para tratar datos.
sqs = boto3.client("sqs") # Cliente de AWS SQS para enviar mensajes a colas.

conversations_table = dynamodb.Table(f"{_DYNAMODB_TABLE_PREFIX}-conversations") # Tabla de DynamoDB para almacenar conversaciones.
deduplication_table = dynamodb.Table(f"{_DYNAMODB_TABLE_PREFIX}-deduplication") # Tabla de DynamoDB para almacenar eventos procesados y evitar duplicados.
channels_table = dynamodb.Table(f"{_DYNAMODB_TABLE_PREFIX}-channels") # Tabla de DynamoDB para almacenar información de canales y relacionarlos con el tenant_id.
tenants_table = dynamodb.Table(f"{_DYNAMODB_TABLE_PREFIX}-tenants") # Tabla de DynamoDB para almacenar información de tenants (clientes).

# Objeto logger configurado para logging estructurado.
logger = logging.getLogger()
logger.setLevel(getattr(logging, _LOG_LEVEL.upper(), logging.INFO))

_SECRETS = {}  # key -> (value, ts)  --  Parámetros cacheados para evitar llamadas repetidas a Parameter Store que aumentarían la latencia. El valor es una tupla con el valor del parámetro y la marca de tiempo de cuándo se obtuvo.

_TENANTS_CACHE = {}  # tenant_id -> tenant_info  --  Cache para la información de tenants, similar a _SECRETS pero con la información completa del tenant obtenida de DynamoDB.
_CHANNELS_CACHE = {} # channel_id -> tenant_id  -- Cache para mapear channel_id a tenant_id, evitando consultas repetidas a DynamoDB.

_GRAPH_BASE = f"https://graph.facebook.com/{_GRAPH_VERSION}" # Base URL para la API de Meta Graph.

# Handler principal para AWS Lambda.
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
  """
  Punto de entrada para AWS Lambda.

  Parámetros:
    event (dict): Evento recibido desde API Gateway (v2 ó v1). Debe contener, como mínimo,
                  requestContext.http.method o httpMethod, rawPath o path, y rawQueryString.
    context: Objeto de contexto de AWS Lambda (no usado explícitamente aquí).

  Comportamiento:
    - Valida endpoint (/webhook/<env>).
    - Rutea por método HTTP a process_get o process_post.
    - Registra errores y devuelve respuestas HTTP apropiadas en forma de dict.
  
  Retorno:
    dict: Estructura con 'statusCode' y 'body' compatible con integraciones de Lambda+API Gateway.

  Excepciones:
    Exception: Se propaga cualquier error inesperado en extracción de datos o routing.
  """
  try:
    # La estructura del evento recibido desde API Gateway v2 está en la línea 75 del código. 
    method = (
      event.get("requestContext", {}).get("http", {}).get("method") 
      or event.get("httpMethod", "")
      or "GET"
    ).upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    raw_qs = event.get("rawQueryString") or ""
    
    # Comprobar que el endpoint es el esperado (en este caso, "/webhook/<env>").
    if raw_path != _WEBHOOK_PATH:
      logger.warning(json.dumps({"message": "Endpoint no encontrado.", "raw_path": raw_path, "event": event}))
      return {"statusCode": 404, "body": "Not Found"}
  except Exception as e:
    logger.error(json.dumps({"message": "Error recuperando los datos del evento.", "error": str(e), "event": event}))
    raise
  
  try:
    # Comparar el método HTTP y procesar en consecuencia.
    match method:
      case "GET":
        return process_get(raw_qs)
      case "POST":
        return process_post(event)
      case _:
        logger.warning(json.dumps({"message": "Método HTTP no permitido.", "method": method, "event": event}))
        return {"statusCode": 405, "body": "Method Not Allowed"}
  except Exception as e:
    logger.error(json.dumps({"message": "Error procesando el webhook.", "error": str(e), "event": event}))
    raise

# Procesar la verificación del webhook de Meta.
def process_get(raw_qs: str) -> dict[str, Any]:
  """
  Procesa la petición GET para verificación del webhook (hub.challenge).

  Parámetros:
    raw_qs (str): Query string raw (por ejemplo "hub.mode=subscribe&hub.verify_token=TOKEN&hub.challenge=123").

  Comportamiento:
    - Parsear parámetros hub.mode, hub.verify_token y hub.challenge.
    - Comparar el verify_token con el valor almacenado en Parameter Store (con cache).
    - Si es válido y mode == 'subscribe', devolver el challenge con status 200.
    - En caso contrario devolver 403 Forbidden.

  Retorno:
    dict: {'statusCode': int, 'body': str}

  Excepciones:
    botocore.exceptions.ClientError: Si falla la lectura del token en Parameter Store.
    Exception: Cualquier error inesperado no controlado explícitamente.
  """
  params = parse_qs(raw_qs)
  
  # La estructura del webhook de verificación está en la línea 119 del código.
  mode = params.get("hub.mode")[0] if params.get("hub.mode") else None
  token = params.get("hub.verify_token")[0] if params.get("hub.verify_token") else None
  challenge = params.get("hub.challenge")[0] if params.get("hub.challenge") else None
  
  VERIFY_TOKEN = get_secret(f"/{_ENV}/meta_verify_token") # El token de verificación se almacena en Parameter Store bajo la clave "meta_verify_token" dentro del entorno correspondiente (dev, prod, etc.).
  
  if not VERIFY_TOKEN or VERIFY_TOKEN == "unknown":
    logger.warning(json.dumps({"message": "No se ha podido obtener el token de verificación para el webhook.", "env": _ENV}))
    return {"statusCode": 500, "body": "Internal Server Error"}
  
  # Comprobar que el modo es "subscribe", que el token es correcto y responder con el challenge.
  if mode and token and mode == "subscribe" and token == VERIFY_TOKEN:
    return {"statusCode": 200, "body": challenge or ""}
  else:
    logger.warning(json.dumps({"message": "Verificación fallida del webhook.", "mode": mode, "token": token}))
    return {"statusCode": 403, "body": "Forbidden"}
  
# Procesar la recepción de un webhook de Meta.
def process_post(event: dict[str, Any]) -> dict[str, Any]:
  """
  Procesa peticiones POST entrantes desde Meta (WhatsApp, Messenger o Instagram).

  Parámetros:
    event (dict): Evento completo desde API Gateway que incluye headers, body (posiblemente base64),
                  y isBase64Encoded.

  Comportamiento:
    - Normaliza headers a minúsculas.
    - Extrae body raw y lo parsea como JSON.
    - Verifica la firma HMAC SHA-256 usando el APP SECRET correspondiente.
    - Extrae channel_id y message_id según tipo de canal.
    - Llama a persist_message para guardar el mensaje (manejo de deduplicación).
  
  Retorno:
    dict: Respuesta HTTP simulada para API Gateway, p.ej. {'statusCode': 200, 'body': 'OK'}.

  Excepciones:
    No propaga excepciones por defecto: captura errores operativos y devuelve respuesta HTTP.
  """
  # La estructura de los webhooks de Meta está en las líneas 2 y 50 del código.
  headers = event.get("headers") or {}
  headers = {k.lower(): v for k, v in headers.items()} # Normalizar claves a lowercase para evitar problemas de mayúsculas/minúsculas.
  
  signature = headers.get("x-hub-signature-256") or ""
  raw_body = get_raw_body(event)
  try:
    body = json.loads(raw_body.decode("utf-8"))
  except json.JSONDecodeError as e:
    logger.warning(json.dumps({"message": "Error al decodificar el cuerpo del webhook como JSON.", "error": str(e), "raw_body": raw_body}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  channel_id = get_channel_id(body)
  if channel_id.endswith("unknown"):
    logger.warning(json.dumps({"message": "Canal desconocido.", "channel_id": channel_id, "body": body}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  message_id = get_message_id(body, channel_id)
  if message_id.endswith("unknown"):
    logger.warning(json.dumps({"message": "No se ha podido extraer el message_id del webhook.", "channel_id": channel_id, "body": body}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  tenant_id = get_channel_info(channel_id).get("tenant_id", "default_tenant")
  if not tenant_id or tenant_id == "default_tenant":
    logger.warning(json.dumps({"message": "No se ha podido encontrar el tenant_id asociado al channel_id.", "channel_id": channel_id, "body": body}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  user_id = get_sender_id(body, channel_id)
  if not user_id or user_id.endswith("unknown"):
    logger.warning(json.dumps({"message": "No se ha podido extraer el sender_id del webhook.", "channel_id": channel_id, "body": body}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  # Verificar la firma del webhook utilizando el APP SECRET correspondiente.  
  if not verify_signature(raw_body, signature, tenant_id):
    logger.warning(json.dumps({"message": "Firma no válida en el webhook recibido.", "headers": headers}))
    return {"statusCode": 403, "body": "Forbidden"}
  
  # Verificar si el usuario está bloqueado antes de procesar el mensaje
  if is_user_blocked(user_id, channel_id):
    logger.warning(json.dumps({"message": "Usuario bloqueado. Mensaje ignorado.", "user_id": user_id, "channel_id": channel_id, "message_id": message_id}))
    return {"statusCode": 200, "body": "OK"}
  
  # Obtener el texto del mensaje para validaciones
  try:
    message_text = get_message_body(body, channel_id)
  except Exception as e:
    logger.error(json.dumps({"message": "Error al extraer el texto del mensaje.", "error": str(e), "channel_id": channel_id}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  if not message_text:
    logger.warning(json.dumps({"message": "Mensaje sin contenido.", "channel_id": channel_id, "user_id": user_id}))
    return {"statusCode": 400, "body": "Bad Request"}
  
  # Verificar si el mensaje es demasiado largo
  if len(message_text) >= _TOO_LONG_MESSAGE_THRESHOLD:
    logger.warning(json.dumps({"message": "Mensaje demasiado largo ignorado.", "user_id": user_id, "channel_id": channel_id, "message_length": len(message_text), "threshold": _TOO_LONG_MESSAGE_THRESHOLD}))
    try:
      access_token = get_secret(f"/{_ENV}/access_token/{channel_id}")
      if channel_id.startswith("wa:"):
        phone_number_id = channel_id.split(":", 1)[1]
        send_wa_reply(phone_number_id, access_token, user_id, _TOO_LONG_MESSAGE_RESPONSE)
      else:
        send_ms_ig_reply(access_token, user_id, _TOO_LONG_MESSAGE_RESPONSE)
    except Exception as e:
      logger.error(json.dumps({"message": "Error al enviar respuesta de mensaje demasiado largo.", "error": str(e), "user_id": user_id, "channel_id": channel_id}))
    return {"statusCode": 200, "body": "OK"}
  
  # Verificar si el usuario está enviando demasiados mensajes (rate limiting)
  if check_and_block_if_too_many_messages(user_id, channel_id):
    logger.warning(json.dumps({"message": "Usuario bloqueado por demasiados mensajes.", "user_id": user_id, "channel_id": channel_id}))
    return {"statusCode": 200, "body": "OK"}
  
  # Persistir el mensaje en DynamoDB, evitando duplicados.
  try:
    return persist_message(tenant_id, channel_id, message_id, user_id, body)
  except Exception as e:
    logger.error(json.dumps({"message": "Error al persistir el mensaje en DynamoDB.", "error": str(e), "channel_id": channel_id, "user_id": user_id, "message_id": message_id}))
    return {"statusCode": 500, "body": "Internal Server Error"}

# Función para obtener el channel_id a partir del body del webhook, dependiendo del tipo de canal (WhatsApp, Instagram o Messenger).
def get_channel_id(body: dict[str, Any]) -> str:
  """
  Extrae el identificador del canal desde el body del webhook.

  Parámetros:
    body (dict): JSON decodificado del webhook.

  Retorno:
    str: channel_id en formato:
         - "wa:{phone_number_id}" para WhatsApp,
         - "ms:{page_id}" para Messenger,
         - "ig:{page_id}" para Instagram,
         o "unknown" si no se pudo extraer.

  Excepciones:
    No propaga excepciones: captura errores de parsing y retorna "unknown".
  """
  try:
    obj = body.get("object", "") if isinstance(body, dict) else ""
    if isinstance(obj, str) and "whatsapp_business_account" in obj:
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      changes = first.get("changes") if isinstance(first.get("changes"), list) else []
      change = changes[0] if len(changes) > 0 and isinstance(changes[0], dict) else {}
      phone_number_id = change.get("value", {}).get("metadata", {}).get("phone_number_id")
      return "wa:" + (phone_number_id or "unknown")

    if isinstance(obj, str) and "page" in obj:
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      page_id = entry[0].get("id") if len(entry) > 0 and isinstance(entry[0], dict) else None
      return "ms:" + (page_id or "unknown")

    if isinstance(obj, str) and "instagram" in obj:
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      ig_id = entry[0].get("id") if len(entry) > 0 and isinstance(entry[0], dict) else None
      return "ig:" + (ig_id or "unknown")

  except (KeyError, TypeError, IndexError, ValueError) as e:
    logger.error(json.dumps({"message": "Error extrayendo el channel_id del body del webhook.", "error": str(e), "body": body}))
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo channel_id.", "error": str(e), "body": body}))

  return "unknown"

# Función para obtener el message_id a partir del body del webhook, dependiendo del tipo de canal (WhatsApp, Instagram o Messenger).
def get_message_id(body: dict[str, Any], channel_id: str) -> str:
  """
  Extrae el identificador del mensaje del webhook.

  Parámetros:
    body (dict): JSON decodificado del webhook.
    channel_id (str): Identificador del canal (output de get_channel_id).

  Retorno:
    str: message_id extraído o "unknown" si no se encuentra.

  Excepciones:
    No propaga excepciones: captura errores de parsing y retorna "unknown".
  """
  try:
    if channel_id.startswith("wa:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      changes = first.get("changes") if isinstance(first.get("changes"), list) else []
      change = changes[0] if len(changes) > 0 and isinstance(changes[0], dict) else {}
      messages = change.get("value", {}).get("messages") if isinstance(change.get("value", {}).get("messages"), list) else []
      mid = messages[0].get("id") if len(messages) > 0 and isinstance(messages[0], dict) else None
      return mid or "unknown"

    if channel_id.startswith("ms:") or channel_id.startswith("ig:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      messaging = first.get("messaging") if isinstance(first.get("messaging"), list) else []
      msg = messaging[0].get("message") if len(messaging) > 0 and isinstance(messaging[0], dict) else {}
      mid = msg.get("mid")
      return mid or "unknown"
  except (KeyError, TypeError, IndexError, ValueError) as e:
    logger.error(json.dumps({"message": "Error extrayendo el message_id del body del webhook.", "error": str(e), "body": body, "channel_id": channel_id}))
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo message_id.", "error": str(e), "body": body, "channel_id": channel_id}))

  return "unknown"

# Función para obtener el sender_id a partir del body del webhook, dependiendo del tipo de canal (WhatsApp, Instagram o Messenger).
def get_sender_id(body: dict[str, Any], channel_id: str) -> str:
  """
  Extrae el identificador del remitente (usuario que envió el mensaje).

  Parámetros:
    body (dict): JSON decodificado del webhook.
    channel_id (str): Identificador del canal (output de get_channel_id).

  Retorno:
    str: sender_id extraído:
         - Número de teléfono (formato internacional) para WhatsApp.
         - PSID (Page-Scoped ID) para Messenger/Instagram.
         - "unknown" si no se encuentra.

  Excepciones:
    No propaga excepciones: captura errores de parsing y retorna "unknown".
  """
  try:
    if channel_id.startswith("wa:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      changes = first.get("changes") if isinstance(first.get("changes"), list) else []
      change = changes[0] if len(changes) > 0 and isinstance(changes[0], dict) else {}
      messages = change.get("value", {}).get("messages") if isinstance(change.get("value", {}).get("messages"), list) else []
      sender = messages[0].get("from") if len(messages) > 0 and isinstance(messages[0], dict) else None
      return sender or "unknown"

    if channel_id.startswith("ms:") or channel_id.startswith("ig:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      messaging = first.get("messaging") if isinstance(first.get("messaging"), list) else []
      sender = messaging[0].get("sender", {}).get("id") if len(messaging) > 0 and isinstance(messaging[0], dict) else None
      return sender or "unknown"
  except (KeyError, TypeError, IndexError, ValueError) as e:
    logger.error(json.dumps({"message": "Error extrayendo el sender_id del body del webhook.", "error": str(e), "body": body, "channel_id": channel_id}))
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo sender_id.", "error": str(e), "body": body, "channel_id": channel_id}))

  return "unknown"

# Función para obtener el message_body a partir del body del webhook, dependiendo del tipo de canal (WhatsApp, Instagram o Messenger).
def get_message_body(body: dict[str, Any], channel_id: str) -> str:
  """
  Extrae el texto del mensaje recibido.

  Parámetros:
    body (dict): JSON decodificado del webhook.
    channel_id (str): Identificador del canal (output de get_channel_id).

  Retorno:
    str: Texto del mensaje o cadena vacía si no se encuentra.

  Excepciones:
    No propaga excepciones: captura errores de parsing y retorna cadena vacía.
  """
  try:
    if channel_id.startswith("wa:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      changes = first.get("changes") if isinstance(first.get("changes"), list) else []
      change = changes[0] if len(changes) > 0 and isinstance(changes[0], dict) else {}
      messages = change.get("value", {}).get("messages") if isinstance(change.get("value", {}).get("messages"), list) else []
      text = messages[0].get("text", {}).get("body") if len(messages) > 0 and isinstance(messages[0], dict) else None
      return text or ""

    if channel_id.startswith("ms:") or channel_id.startswith("ig:"):
      entry = body.get("entry") if isinstance(body.get("entry"), list) else []
      first = entry[0] if len(entry) > 0 and isinstance(entry[0], dict) else {}
      messaging = first.get("messaging") if isinstance(first.get("messaging"), list) else []
      msg = messaging[0].get("message") if len(messaging) > 0 and isinstance(messaging[0], dict) else {}
      text = msg.get("text")
      return text or ""
  except (KeyError, TypeError, IndexError, ValueError) as e:
    logger.error(json.dumps({"message": "Error extrayendo el message_body del body del webhook.", "error": str(e), "body": body, "channel_id": channel_id}))
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo message_body.", "error": str(e), "body": body, "channel_id": channel_id}))

  return ""

def send_ms_ig_reply(page_access_token: str, psid: str, text: str) -> dict:
  """
  Envía una respuesta a un usuario de Messenger o Instagram mediante la API de Meta Graph.

  Parámetros:
    page_access_token (str): Token de acceso de la página (página_id de Facebook/Instagram).
    psid (str): Identificador único del usuario en la plataforma (PSID).
    text (str): Texto del mensaje a enviar.

  Retorno:
    dict: Respuesta JSON de la API de Meta Graph.

  Excepciones:
    requests.HTTPError: Si la respuesta HTTP indica error.
    requests.RequestException: Para errores de conexión o timeout.
  """
  url = f"{_GRAPH_BASE}/me/messages"
  payload = {
      "recipient": {"id": psid},
      "message": {"text": text},
  }
  return post_reply(url, page_access_token, payload)

def send_wa_reply(phone_number_id: str, token: str, to_wa_id: str, text: str) -> dict:
  """
  Envía una respuesta a un usuario de WhatsApp mediante la API de Meta Graph.

  Parámetros:
    phone_number_id (str): Identificador del número de teléfono registrado en WhatsApp Business Account.
    token (str): Token de acceso para autenticación en Meta Graph API.
    to_wa_id (str): Identificador de WhatsApp del usuario (número de teléfono en formato internacional).
    text (str): Texto del mensaje a enviar.

  Retorno:
    dict: Respuesta JSON de la API de Meta Graph.

  Excepciones:
    requests.HTTPError: Si la respuesta HTTP indica error.
    requests.RequestException: Para errores de conexión o timeout.
  """
  url = f"{_GRAPH_BASE}/{phone_number_id}/messages"
  payload = {
      "messaging_product": "whatsapp",
      "to": to_wa_id,
      "type": "text",
      "text": {"body": text},
  }
  return post_reply(url, token, payload)

# Función para enviar una respuesta al usuario.
def post_reply(url: str, token: str, payload: dict) -> dict:
    """
    Envía una petición POST al endpoint especificado con autorización Bearer y devuelve el JSON.

    Parámetros:
      url (str): URL del endpoint al que se enviará la petición.
      token (str): Token de autorización (Bearer).
      payload (dict): Cuerpo de la petición que se enviará como JSON.

    Retorno:
      dict: Respuesta decodificada desde JSON.

    Excepciones:
      requests.HTTPError: Si la respuesta HTTP indica error (se lanza `raise_for_status()`).
      requests.RequestException: Para errores de conexión o timeout.
    """
    r = requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_REQUEST_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    return r.json()

def persist_message(tenant_id: str, channel_id: str, message_id: str, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
  """
  Persiste el mensaje en DynamoDB con lógica de deduplicación y actualización/creación de conversación.

  Parámetros:
    tenant_id (str): Identificador del tenant asociado al canal.
    channel_id (str): Identificador del canal (formato "wa:...", "ms:..." o "ig:...").
    message_id (str): Identificador único del mensaje dentro del canal.
    user_id (str): Identificador del usuario.
    body (dict): JSON decodificado del webhook.

  Comportamiento:
    - Inserta una entrada en la tabla de deduplicación con condición para que falle si ya existe (evita duplicados).
    - Actualiza o crea un item en la tabla de conversaciones: añade el texto al campo pending_messages,
      actualiza estado, last_message_time y expires_at.
    - Usa transact_write_items para asegurar atomicidad entre deduplicación y upsert.
    
  Manejo de Deduplicación (Comportamiento Esperado):
    - Si el mensaje ya existe en la tabla de deduplicación (ConditionalCheckFailedException):
      * Devuelve 200 OK sin logging explícito de error.
      * No intenta procesar el mensaje nuevamente (comportamiento idempotente).
    - Si ocurre cualquier otro error en DynamoDB:
      * Registra el error en CloudWatch con detalles del incidente.
      * Re-lanza la excepción para que AWS Lambda maneje el reintentos.

  Retorno:
    dict: Respuesta compatible con API Gateway: p.ej. {'statusCode': 200, 'body': 'OK'} o errores 400/500.
  
  Excepciones:
    - Re-lanza excepciones de boto3 que no sean ConditionalCheckFailedException.
  """
  try:
    # Guardar el mensaje en la tabla de deduplicación para evitar procesar mensajes duplicados.
    now = time()
    expires_at = now + _DEDUP_TTL_HOURS * 3600  # El TTL de DynamoDB se establece según la configuración para que los registros de deduplicación expiren automáticamente después de ese tiempo.

    try:
      message_text = get_message_body(body, channel_id)
    except Exception as e:
      logger.error(json.dumps({"message": "Error llamando a get_message_body.", "error": str(e), "body": body, "channel_id": channel_id}))
      return {"statusCode": 400, "body": "Bad Request"}

    if not message_text:
      logger.warning(json.dumps({"message": "No se ha podido extraer el message_body del webhook.", "channel_id": channel_id, "body": body}))
      return {"statusCode": 400, "body": "Bad Request"}
    
    dynamodb.meta.client.transact_write_items(
      TransactItems=[
        # 1) Deduplicación: insertar solo si no existe (channel_id, message_id)
        {
          "Put": {
            "TableName": deduplication_table.name,
            "Item": {
              "channel_id": {"S": channel_id},
              "message_id": {"S": message_id},
              "created_at": {"N": str(now)},
              "expires_at": {"N": str(expires_at)},
            },
            "ConditionExpression": "attribute_not_exists(channel_id)",
          }
        },

        # 2) Upsert conversation: si existe, append + actualizar tiempos/estado.
        #    si no existe, se crea con esos valores.
        {
          "Update": {
            "TableName": conversations_table.name,
            "Key": {
              "channel_id": {"S": channel_id},
              "user_id": {"S": user_id},
            },
            "UpdateExpression": (
              "SET "
              "#pending = list_append(if_not_exists(#pending, :empty_list), :new_msgs), "
              "#times = list_append(if_not_exists(#times, :empty_list), :new_times), "
              "#status = :waiting, "
              "#last_time = :now, "
              "#expires = :expires_at"
            ),
            "ExpressionAttributeNames": {
              "#pending": "pending_messages",
              "#times": "message_times",
              "#status": "status",
              "#last_time": "last_message_time",
              "#expires": "expires_at",
            },
            "ExpressionAttributeValues": {
              ":empty_list": {"L": []},
              ":new_msgs": {"L": [{"S": message_text}]},
              ":new_times": {"L": [{"N": str(now)}]},
              ":waiting": {"S": "waiting"},
              ":now": {"N": str(now)},
              ":expires_at": {"N": str(expires_at)},
            },
          }
        },
      ],
      ReturnCancellationReasons=True,
    )
    
    tenant_info = get_tenant_info(tenant_id) # Obtener la información del tenant para verificar el estado del servicio.
    
    service_status = tenant_info.get("service_status", "unknown") # El campo "service_status" en la tabla de tenants indica si el servicio para ese tenant está activo o no. Si no existe, se considera "unknown".
    
    if service_status != _ACTIVE_SERVICE_STATUS: # Si el servicio no está activo, enviar un mensaje al usuario informando que el servicio no está disponible temporalmente.
      inactive_message = tenant_info.get("inactive_message", "unknown")
      
      if not inactive_message or inactive_message == "unknown":
        inactive_message = _INACTIVE_SERVICE_MESSAGE  # Mensaje por defecto si no se ha configurado uno específíco para el tenant.
      
      access_token = get_secret(f"/{_ENV}/access_token/{channel_id}")
      
      if channel_id.startswith("wa:"):
        phone_number_id = channel_id.split(":", 1)[1]
        send_wa_reply(phone_number_id, access_token, user_id, inactive_message)
      else:
        send_ms_ig_reply(access_token, user_id, inactive_message)
      
      logger.warning(json.dumps({"message": "El tenant asociado al canal no está activo.", "tenant_id": tenant_id, "channel_id": channel_id, "service_status": service_status}))  
    else:
      try:
        dynamodb.meta.client.update_item(
            TableName=conversations_table.name,
            Key={
                "channel_id": {"S": channel_id},
                "user_id": {"S": user_id},
            },
            ConditionExpression="attribute_not_exists(queued) OR queued = :f",
            UpdateExpression="SET queued = :q, queue_id = :mid",
            ExpressionAttributeValues={
                ":q": {"BOOL": True},
                ":f": {"BOOL": False},
                ":mid": {"S": message_id},
            }
        )
        sqs_response = sqs.send_message(
          QueueUrl=_QUEUE_URL,
          DelaySeconds=_SQS_DELAY_SECONDS,
          MessageBody=json.dumps({
            "channel_id": channel_id,
            "user_id": user_id,
            "message_id": message_id,
          })
        )
        
        if sqs_response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
          logger.error(json.dumps({"message": "Error al enviar el mensaje a SQS.", "sqs_response": sqs_response, "channel_id": channel_id, "user_id": user_id, "message_id": message_id}))
          # Si falla el envío a SQS, se podría considerar marcar la conversación como no encolada para reintentar después, pero eso dependería de la lógica de reintentos que se quiera implementar.
          dynamodb.meta.client.update_item(
            TableName=conversations_table.name,
            Key={
                "channel_id": {"S": channel_id},
                "user_id": {"S": user_id},
            },
            UpdateExpression="SET queued = :q, queue_id = :mid",
            ExpressionAttributeValues={
                ":q": {"BOOL": False},
                ":mid": {"S": "0000000000000000000"}, # Un valor de message_id que indique que no se ha podido encolar, para diferenciarlo de los mensajes que sí están encolados pero aún no procesados.
            }
          )
          return {"statusCode": 500, "body": "Internal Server Error"}
      except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
          dynamodb.meta.client.update_item(
            TableName=conversations_table.name,
            Key={
                "channel_id": {"S": channel_id},
                "user_id": {"S": user_id},
            },
            UpdateExpression="SET queue_id = :mid",
            ExpressionAttributeValues={
                ":mid": {"S": message_id}
            }
          )
  
    return {"statusCode": 200, "body": "OK"}
    
  except ClientError as e:
    if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
      return {"statusCode": 200, "body": "OK"} # Si la excepción es ConditionalCheckFailedException, significa que el mensaje ya existe en la tabla de deduplicación, por lo que es un mensaje duplicado.
    else:
      logger.error(json.dumps({"message": "Error al persistir el mensaje en DynamoDB.", "error": str(e), "channel_id": channel_id, "message_id": message_id, "body": body}))
      raise

# Función para obtener el body en formato bytes, decodificando de base64 si es necesario.
def get_raw_body(event) -> bytes:
  """
  Devuelve el cuerpo del evento en bytes, decodificando base64 si corresponde.

  Parámetros:
    event (dict): Evento de API Gateway (v2) con campos 'body' e 'isBase64Encoded'.
                  El body puede estar codificado en base64 según el valor de isBase64Encoded.

  Retorno:
    bytes: Contenido del body en bytes (decodificado de base64 si aplica).
           Listo para verificar firma HMAC o parsear como JSON.
  """
  body = event.get("body") or ""
  if event.get("isBase64Encoded"):
    return base64.b64decode(body)
  return body.encode("utf-8")

# Función para verificar la firma del webhook
def verify_signature(raw_body: bytes, header_sig: str, tenant_id: str) -> bool:
  """
  Verifica la firma HMAC SHA-256 del webhook comparando header con el HMAC calculado.

  Parámetros:
    raw_body (bytes): Cuerpo en bytes del request (sin modificaciones).
    header_sig (str): Valor de la cabecera 'x-hub-signature-256' (formato: 'sha256=<hexdigest>').
    tenant_id (str): Identificador del tenant para obtener el APP SECRET correspondiente desde Parameter Store.

  Retorno:
    bool: True si la firma es válida, False en caso contrario.
          Devuelve False si el header no tiene formato válido o si no se obtiene el APP SECRET.

  Nota:
    Utiliza hmac.compare_digest() para evitar timing attacks.
  """
  if not header_sig or not header_sig.startswith("sha256="):
    return False
  
  APP_SECRET = get_secret(f"/{_ENV}/app_secret/{tenant_id}")
  
  if not APP_SECRET or APP_SECRET == "unknown":
    logger.warning(json.dumps({"message": "No se ha podido obtener el APP SECRET para verificar la firma del webhook.", "tenant_id": tenant_id}))
    return False
  
  received = header_sig.split("=", 1)[1]
  expected = hmac.new(APP_SECRET.encode("utf-8"), raw_body, digestmod=hashlib.sha256).hexdigest()
          
  # Compara la firma esperada con la recibida
  return hmac.compare_digest(expected, received)

# Función para obtener la información del tenant desde DynamoDB, con cache local para reducir latencia en llamadas repetidas.
def get_tenant_info(tenant_id: str) -> dict:
  """
  Obtiene la información del tenant desde DynamoDB con cache local.

  Parámetros:
    tenant_id (str): Identificador único del tenant (cliente).

  Retorno:
    dict: Diccionario con información del tenant (service_status, inactive_message, etc.)
         obtenida de DynamoDB en formato de bajo nivel (con tipos DynamoDB).
         Devuelve dict vacío si no se encuentra en caché ni en DynamoDB.

  Nota:
    El campo "service_status" debe ser "active" para procesar mensajes.
    Utiliza caché local con TTL de _CACHE_TTL_SECONDS segundos.
  """
  global _TENANTS_CACHE
  now = time()

  # Comprobar cache local primero (tenant_id -> (tenant_info, ts)).
  if tenant_id in _TENANTS_CACHE:
    tenant_info, ts = _TENANTS_CACHE[tenant_id]
    if now - ts < _CACHE_TTL_SECONDS:
      return tenant_info

  # Obtener desde DynamoDB si no está en cache o ha expirado.
  try:
    resp = dynamodb.meta.client.get_item(
        TableName=tenants_table.name,
        Key={"tenant_id": {"S": tenant_id}}
    )
    tenant_info = resp.get("Item", {})
    _TENANTS_CACHE[tenant_id] = (tenant_info, now) # Guardar en cache local
    return tenant_info
  except ClientError as e:
    logger.warning(json.dumps({"message": "Error al intentar recuperar la información del tenant desde DynamoDB.", "tenant_id": tenant_id, "error": str(e)}))
    raise
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo tenant_info.", "error": str(e), "tenant_id": tenant_id}))
    raise

def get_channel_info(channel_id: str) -> dict:
  """
  Obtiene la información del canal desde DynamoDB con cache local.

  Parámetros:
    channel_id (str): Identificador del canal (formato "wa:...", "ms:..." o "ig:...").

  Retorno:
    dict: Diccionario con información del canal (incluyendo tenant_id, settings, etc.)
         obtenida de DynamoDB en formato de bajo nivel (con tipos DynamoDB).
         Devuelve dict vacío si no se encuentra en caché ni en DynamoDB.

  Nota:
    Utiliza caché local con TTL de _CACHE_TTL_SECONDS segundos para reducir llamadas a DynamoDB.
  """
  global _CHANNELS_CACHE
  now = time()

  # Comprobar cache local primero (channel_id -> (channel_info, ts)).
  if channel_id in _CHANNELS_CACHE:
    channel_info, ts = _CHANNELS_CACHE[channel_id]
    if now - ts < _CACHE_TTL_SECONDS:
      return channel_info

  # Obtener desde DynamoDB si no está en cache o ha expirado.
  try:
    resp = dynamodb.meta.client.get_item(
        TableName=channels_table.name,
        Key={"channel_id": {"S": channel_id}}
    )
    channel_info = resp.get("Item", {})
    _CHANNELS_CACHE[channel_id] = (channel_info, now) # Guardar en cache local
    return channel_info
  except ClientError as e:
    logger.warning(json.dumps({"message": "Error al intentar recuperar la información del canal desde DynamoDB.", "channel_id": channel_id, "error": str(e)}))
    raise
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error extrayendo channel_info.", "error": str(e), "channel_id": channel_id}))
    raise

def is_user_blocked(user_id: str, channel_id: str) -> bool:
  """
  Verifica si un usuario está bloqueado consultando la lista de usuarios bloqueados en la tabla channels.

  Parámetros:
    user_id (str): Identificador del usuario.
    channel_id (str): Identificador del canal (formato "wa:...", "ms:..." o "ig:...").

  Retorno:
    bool: True si el usuario está bloqueado; False en caso contrario.

  Nota:
    Obtiene la lista de usuarios bloqueados desde la columna 'blocked_users' en la tabla channels.
    Devuelve False si no se puede acceder a DynamoDB (fallo abierto).
  """
  try:
    # Obtener la información del canal (incluye la lista de usuarios bloqueados)
    channel_info = get_channel_info(channel_id)
    
    # Si no hay información del canal, devolver False
    if not channel_info:
      return False
    
    # Obtener la lista de usuarios bloqueados desde el campo 'blocked_users'
    blocked_users_data = channel_info.get("blocked_users", {"L": []})
    blocked_users_list = blocked_users_data.get("L", [])
    
    # Verificar si el user_id está en la lista de usuarios bloqueados
    for blocked_user in blocked_users_list:
      if blocked_user.get("S") == user_id:
        return True
    
    return False
  except ClientError as e:
    logger.warning(json.dumps({"message": "Error al verificar si el usuario está bloqueado.", "user_id": user_id, "channel_id": channel_id, "error": str(e)}))
    return False  # Fallo abierto: permitir el mensaje si no se puede consultar
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error verificando si usuario está bloqueado.", "error": str(e), "user_id": user_id, "channel_id": channel_id}))
    return False  # Fallo abierto: permitir el mensaje

def check_and_block_if_too_many_messages(user_id: str, channel_id: str) -> bool:
  """
  Verifica si un usuario ha enviado demasiados mensajes en un corto periodo de tiempo.
  Si es así, bloquea al usuario agregándolo a la lista de blocked_users en la tabla channels.

  Parámetros:
    user_id (str): Identificador del usuario.
    channel_id (str): Identificador del canal (formato "wa:...", "ms:..." o "ig:...").

  Retorno:
    bool: True si el usuario fue bloqueado; False en caso contrario.

  Nota:
    Consulta el campo 'message_times' de la conversación para contar mensajes recientes.
    Mantiene un registro de timestamps de los últimos mensajes en la tabla de conversaciones.
    Agrega el usuario a la lista 'blocked_users' en la tabla channels.
  """
  try:
    now = time()
    time_threshold = now - _TOO_MANY_MESSAGES_TIME_SECONDS
    
    # Obtener el registro de conversación actual
    resp = dynamodb.meta.client.get_item(
        TableName=conversations_table.name,
        Key={
            "channel_id": {"S": channel_id},
            "user_id": {"S": user_id}
        }
    )
    
    # Si no hay conversación previa, es el primer mensaje (no bloquear)
    if "Item" not in resp:
      return False
    
    item = resp["Item"]
    
    # Obtener los timestamps de los mensajes recientes
    message_times_list = item.get("message_times", {"L": []}).get("L", [])
    
    # Contar cuántos mensajes fueron enviados en los últimos _TOO_MANY_MESSAGES_TIME_SECONDS segundos
    recent_message_count = 0
    for ts_item in message_times_list:
      try:
        ts = int(ts_item.get("N", 0))
        if ts > time_threshold:
          recent_message_count += 1
      except (ValueError, TypeError):
        continue
    
    # Incluir el mensaje actual en el conteo
    recent_message_count += 1
    
    # Si hay demasiados mensajes recientes, bloquear al usuario
    if recent_message_count >= _TOO_MANY_MESSAGES_THRESHOLD:
      # Obtener la información actual del canal
      channel_info = get_channel_info(channel_id)
      
      # Obtener la lista actual de usuarios bloqueados
      blocked_users_data = channel_info.get("blocked_users", {"L": []})
      blocked_users_list = blocked_users_data.get("L", [])
      
      # Verificar si el usuario ya está bloqueado
      is_already_blocked = any(blocked_user.get("S") == user_id for blocked_user in blocked_users_list)
      
      if not is_already_blocked:
        # Agregar el usuario a la lista de bloqueados
        blocked_users_list.append({"S": user_id})
        
        # Actualizar la tabla channels con la nueva lista de usuarios bloqueados
        dynamodb.meta.client.update_item(
            TableName=channels_table.name,
            Key={"channel_id": {"S": channel_id}},
            UpdateExpression="SET blocked_users = :blocked_users",
            ExpressionAttributeValues={
                ":blocked_users": {"L": blocked_users_list}
            }
        )
        
        # Invalidar el caché del canal para que se recargue la próxima vez
        if channel_id in _CHANNELS_CACHE:
          del _CHANNELS_CACHE[channel_id]
      
      return True
    
    return False
  except ClientError as e:
    logger.warning(json.dumps({"message": "Error al verificar rate limit del usuario.", "user_id": user_id, "channel_id": channel_id, "error": str(e)}))
    return False  # Fallo abierto: permitir el mensaje si no se puede consultar
  except Exception as e:
    logger.error(json.dumps({"message": "Unexpected error verificando rate limit.", "error": str(e), "user_id": user_id, "channel_id": channel_id}))
    return False  # Fallo abierto: permitir el mensaje

# Función para obtener parámetros de AWS Systems Manager Parameter Store.
def get_secret(secret_id: str) -> str:
  """
  Recupera un parámetro desde AWS Systems Manager Parameter Store con caché local.

  Parámetros:
    secret_id (str): Nombre del parámetro en Parameter Store. Ejemplos:
                     - "{env}/meta_verify_token"
                     - "{env}/app_secret/{tenant_id}"
                     - "{env}/access_token/{channel_id}"

  Comportamiento:
    - Comprueba la caché local `_SECRETS` y devuelve el valor si no ha expirado (TTL: _CACHE_TTL_SECONDS segundos).
    - Si no está en caché o ha expirado, recupera el parámetro desde Parameter Store con desencriptación.
    - Almacena resultado en `_SECRETS` como tupla `(value, timestamp)`.
    - Devuelve "unknown" si no se obtiene respuesta o parámetro no existe.

  Retorno:
    str: Valor del parámetro si existe; "unknown" si no se encontró o falló la lectura.

  Excepciones:
    botocore.exceptions.ClientError: Se propaga después de logging. Casos comunes:
        - ParameterNotFound: el parámetro no existe en Parameter Store.
        - AccessDeniedException: credenciales sin permisos (ssm:GetParameter).
        - DecryptionFailure: fallo al desencriptar SecureString.
        - ValidationException, InternalServiceError: otros errores de servicio.
      El llamador debe capturar ClientError para manejar estos errores.
  """
  global _SECRETS
  now = time()

  # Comprobar cache local primero (key -> (value, ts)).
  if secret_id in _SECRETS:
    value, ts = _SECRETS[secret_id]
    if now - ts < _CACHE_TTL_SECONDS:
      return value

  # Obtener desde Parameter Store si no está en cache o ha expirado.
  try:
    resp = sm.get_parameter(Name=secret_id, WithDecryption=True)
  except ClientError as e:
    logger.warning(json.dumps({"message": "Error al intentar recuperar el parámetro desde Parameter Store.", "secret_id": secret_id, "error": str(e)}))
    raise

  if not resp:
    logger.warning(json.dumps({"message": "No se ha obtenido respuesta al intentar recuperar el parámetro.", "secret_id": secret_id}))
    return "unknown"

  # El valor se retorna en la clave 'Value' del objeto 'Parameter'.
  if "Parameter" in resp:
    value = resp["Parameter"].get("Value")
    # Guardar en cache local
    try:
      _SECRETS[secret_id] = (value, now)
    except Exception:
      # No debe fallar el flujo por cache; seguir devolviendo el valor.
      pass
    return value

  return "unknown"