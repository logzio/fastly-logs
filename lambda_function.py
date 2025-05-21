import base64
import hashlib
import json
import logging
import time
import urllib.request
import urllib.error
from typing import Dict, Tuple, Union
from version import __version__

logger = logging.getLogger()
logger.setLevel(logging.INFO)  

HEALTH_CHECK_PATH = "/.well-known/fastly/logging/challenge"
LOGZIO_PORT = 8071
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 2
RETRYABLE_STATUS_CODES = {500, 502, 503, 504}
USER_AGENT = f"fastly-logs-{__version__}"

class ConfigurationError(Exception):
    """Raised when there's an issue with user configuration."""
    pass

def get_user_config(query_params: Dict) -> Dict:
    """
    Retrieve user-specific configuration based on query parameters.
    
    Required query parameters:
    - service_id: The Fastly Service ID
    - token: The Logz.io token
    - host: The Logz.io listener host
    
    Optional query parameters:
    - type: The Logz.io log type (default: fastly-logs)
    
    Returns a configuration dictionary:
    {
        'fastly_service_id': 'SERVICE_ID',                      # User's Fastly service ID
        'logzio_token': 'USER_TOKEN',                           # User's Logz.io token
        'logzio_listener_host': 'listener.logz.io',             # User's Logz.io listener host
        'logzio_type': 'user_log_type',                         # User's log type
    }
    """
    service_id = query_params.get('service_id', '').strip()
    token = query_params.get('token')
    host = query_params.get('host')
    
    missing_params = []
    if not service_id:
        missing_params.append('service_id')
    if not token:
        missing_params.append('token')
    if not host:
        missing_params.append('host')
    
    if missing_params:
        raise ConfigurationError(f"Missing required parameters: {', '.join(missing_params)}")
    
    log_type = query_params.get('type', 'fastly-logs')
    
    return {
        'fastly_service_id': service_id,
        'logzio_token': token,
        'logzio_listener_host': host,
        'logzio_type': log_type
    }

def calculate_sha256_hash(service_id: str) -> str:
    hash_obj = hashlib.sha256(service_id.encode())
    return hash_obj.hexdigest() + '\n'

def get_logzio_url(config: Dict) -> str:
    host = config.get('logzio_listener_host')
    token = config.get('logzio_token')
    log_type = config.get('logzio_type')
    
    missing_params = []
    if not host:
        missing_params.append('logzio_listener_host')
    if not token:
        missing_params.append('logzio_token')
    if not log_type:
        missing_params.append('logzio_type')
    
    if missing_params:
        raise ConfigurationError(f"Missing required Logz.io configuration: {', '.join(missing_params)}")
    
    return f"https://{host}:{LOGZIO_PORT}?token={token}&type={log_type}"

def _attempt_logzio_forward(url: str, body: Union[str, bytes], headers: Dict[str, str]) -> Tuple[int, str]:
    """Helper function to make a single attempt to forward logs to Logz.io."""
    try:
        req = urllib.request.Request(
            url,
            data=body if isinstance(body, bytes) else body.encode('utf-8'),
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        logger.error(f"Unexpected error occurred in _attempt_logzio_forward: {type(e).__name__}: {str(e)}")
        return 0, str(e)

def forward_to_logzio(body: Union[str, bytes], is_gzipped: bool, config: Dict) -> Tuple[int, str]:
    url = get_logzio_url(config)
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT
    }
    
    if is_gzipped:
        headers['Content-Encoding'] = 'gzip'
    
    attempt = 0
    last_status = 0
    last_response = ""
    
    while attempt <= MAX_RETRIES:
        attempt += 1
        logger.info(f"Attempt {attempt} of {MAX_RETRIES + 1} to forward to Logz.io...")
        
        status_code, response_body = _attempt_logzio_forward(url, body, headers)
        last_status, last_response = status_code, response_body
        
        # Success case
        if 200 <= status_code < 300:
            return status_code, response_body
            
        # Don't retry client errors (4xx)
        if 400 <= status_code < 500:
            logger.error(f"Client error from Logz.io (not retrying): Status {status_code}, Response: {response_body}")
            return status_code, response_body
            
        # For server errors or network issues that we want to retry
        if status_code in RETRYABLE_STATUS_CODES or status_code == 0:
            logger.warning(f"Retryable error from Logz.io: Status {status_code}, Response: {response_body}")
            logger.info(f"Waiting {RETRY_DELAY_SECONDS} seconds before retry...")
            time.sleep(RETRY_DELAY_SECONDS)
            continue
                
        break
    
    logger.error(f"Failed to forward to Logz.io after {MAX_RETRIES + 1} attempts. "
                f"Last status: {last_status}, Last response: {last_response}")
    return last_status, last_response

def handle_health_check(query_params: Dict) -> Dict:
    try:
        user_config = get_user_config(query_params)
        service_id = user_config['fastly_service_id']
        response_body = calculate_sha256_hash(service_id)
        
        logger.debug(f"Health check response for service_id {service_id}: {response_body}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'body': response_body
        }
    except ConfigurationError as e:
        logger.error(f"Configuration error during health check: {str(e)}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'text/plain'},
            'body': f'Configuration error: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Internal server error'
        }

def handle_logs(event: Dict, query_params: Dict) -> Dict:
    """Handle log forwarding from Fastly to Logz.io."""
    try:
        user_config = get_user_config(query_params)
        
        body = event.get('body', '')
        is_base64 = event.get('isBase64Encoded', False)
        headers = {k.lower(): v for k, v in event.get('headers', {}).items()}
        is_gzipped = headers.get('content-encoding', '').lower() == 'gzip'
        
        logger.debug("Request details:")
        logger.debug(f"Headers: {json.dumps(headers)}")
        logger.debug(f"Is Base64: {is_base64}")
        logger.debug(f"Is Gzipped: {is_gzipped}")
        logger.debug(f"First 500 chars of body: {body[:500]}")
        
        # Log request details
        logger.info(
            f"Received request: Path={event.get('rawPath')}, "
            f"Method={event.get('requestContext', {}).get('http', {}).get('method')}, "
            f"Service ID={user_config['fastly_service_id']}"
        )
        
        if is_base64:
            body = base64.b64decode(body)
            logger.debug("Decoded base64 body")
        elif is_gzipped:
            body = body.encode('utf-8')
            logger.debug("Encoded body to bytes for gzip handling")
        
        status_code, response_body = forward_to_logzio(body, is_gzipped, user_config)
        
        if 200 <= status_code < 300:
            logger.info(f"Successfully forwarded logs to Logz.io for service ID: {user_config['fastly_service_id']}")
            logger.debug(f"Logz.io response: {response_body}")
        else:
            logger.error(
                f"Failed to forward logs to Logz.io. Status: {status_code}, "
                f"Response: {response_body}, Service ID: {user_config['fastly_service_id']}"
            )
        
        # Always return 200 to Fastly, even if forwarding failed
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'OK'
        }
        
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}")
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'OK'
        }

def lambda_handler(event: Dict, context: Dict) -> Dict:
    """Main Lambda handler."""
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        
        logger.info(f"Raw query string: {event.get('rawQueryString', 'NONE')}")
        
        debug = query_params.get('debug', '').lower() == 'true'
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Raw event: {json.dumps(event)}")
            logger.debug(f"Query parameters: {json.dumps(query_params)}")
        else:
            logger.setLevel(logging.INFO)
        
        path = event.get('rawPath', '')
        
        if path == HEALTH_CHECK_PATH and event.get('requestContext', {}).get('http', {}).get('method') == 'GET':
            return handle_health_check(query_params)
        
        if event.get('requestContext', {}).get('http', {}).get('method') == 'POST':
            return handle_logs(event, query_params)
        
        # Handle unknown requests
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Not Found'
        }
        
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Internal Server Error'
        } 