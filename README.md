# Fastly to Logz.io Log Forwarder

This AWS Lambda function serves as an HTTPS logging endpoint for Fastly and forwards received logs to Logz.io. It handles both Fastly's health check mechanism and log forwarding functionality, with configuration managed via URL query parameters.

## Quick Start Guide for Customers

### 1. Check Required Parameters

Before creating your Fastly endpoint, review the [URL Parameters Reference](#url-parameters-reference) section below to understand the required and optional parameters you'll need to include in your endpoint URL.

### 2. Create a Logz.io HTTPS Endpoint in Fastly

1. Log into your Fastly account and select your service
2. Go to **Logging** → **Create a new endpoint** → **HTTPS**
3. Configure the following settings:

| Setting | Value |
|---------|-------|
| Name | `Logz.io Logs` (or any name you prefer) |
| URL | `https://s9o4regaob.execute-api.us-east-1.amazonaws.com/?service_id=YOUR_SERVICE_ID&token=YOUR_LOGZIO_TOKEN&host=YOUR_LOGZIO_HOST` |
| Method | `POST` |
| Format Version | `2` |
| Response Condition | Leave empty |
| Content Type | `application/json` |
| Maximum Batch Size | `0` (no limit) or your preferred size |
| JSON log entry format | Use newline-delimited JSON |
| Request Compression | Gzip (optional but recommended) |

### 3. Use This JSON Log Format

Copy and paste this log format into your Fastly HTTPS endpoint configuration:

```json
{"@timestamp":"%{begin:%Y-%m-%dT%H:%M:%SZ}t","time_elapsed_msec":"%{time.elapsed.msec}V","is_tls":"%{if(req.is_ssl, \"true\", \"false\")}V","client_ip":"%h","message":"%m %U returned %>s for %h on %v in %{time.elapsed.msec}Vms (UA: %{User-Agent}i, Cache: %{fastly_info.state}V)" ,"client_geo_city":"%{client.geo.city}V","client_geo_country_code":"%{client.geo.country_code}V","client_geo_continent_code":"%{client.geo.continent_code}V","client_geo_region":"%{client.geo.region}V","http_host":"%v","http_method":"%m","http_url":"%U","http_protocol":"%H","http_status_code":"%>s","http_referer":"%{Referer}i","http_user_agent":"%{User-Agent}i","bytes_received_from_client":"%I","bytes_sent_to_client":"%O","resp_content_type":"%{Content-Type}o","fastly_service_id":"%{req.service_id}V","fastly_service_version":"%{req.vcl.version}V","fastly_pop":"%{server.identity}V","fastly_region":"%{server.region}V","fastly_cache_status":"%{fastly_info.state}V","fastly_is_h2":"%{if(fastly_info.is_h2, \"true\", \"false\")}V","fastly_is_h3":"%{if(fastly_info.is_h3, \"true\", \"false\")}V","tls_client_protocol":"%{tls.client.protocol}V","tls_client_cipher":"%{tls.client.cipher}V","tls_client_ciphers_sha":"%{tls.client.ciphers_sha}V","tls_client_iana_chosen_cipher_id":"%{tls.client.iana_chosen_cipher_id}V","fastly_error_details":"%{fastly.error}V"}
```

### 4. Complete the URL Parameters

Your URL should include the following required parameters:

```
https://s9o4regaob.execute-api.us-east-1.amazonaws.com/?service_id=YOUR_SERVICE_ID&token=YOUR_LOGZIO_TOKEN&host=YOUR_LOGZIO_HOST
```

Replace:
- `YOUR_SERVICE_ID` with your Fastly Service ID
- `YOUR_LOGZIO_TOKEN` with your Logz.io shipping token
- `YOUR_LOGZIO_HOST` with your Logz.io listener host (e.g., `listener.logz.io` or region-specific host)

For region-specific listener hosts, refer to the [Logz.io Regions documentation](https://docs.logz.io/docs/user-guide/admin/hosting-regions/account-region/).

### 5. Viewing Your Logs in Logz.io

After configuring the endpoint:
1. Generate some traffic to your Fastly service
2. Wait a few moments (typically less than 1 minute) for logs to appear
3. Log into your Logz.io account
4. Go to the Logs tab
5. Search for `type:fastly-logs` to see your Fastly logs (or `type:YOUR_CUSTOM_TYPE` if you specified a custom type using the `type` parameter)

## URL Parameters Reference

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `service_id` | Yes | Your Fastly Service ID | `service_id=YOUR_SERVICE_ID` |
| `token` | Yes | Your Logz.io logs shipping token | `token=YOUR_LOGZIO_TOKEN` |
| `host` | Yes | The Logz.io listener host address (may vary by region) | `host=listener.logz.io` or `host=listener-eu.logz.io` |
| `type` | No | Custom log type to be assigned in Logz.io (default: `fastly-logs`) | `type=my-custom-logs` |
| `debug` | No | Set to `true` to enable debug logging (default: `false`) | `debug=true` |

## Technical Implementation Details

### Architecture Overview

This implementation follows this flow:

1. **Request Handling**: AWS API Gateway receives requests from Fastly
2. **Lambda Processing**:
   - Validates query parameters
   - Handles health checks (required by Fastly)
   - Processes incoming log data
   - Forwards logs to Logz.io
3. **Response**: Returns appropriate responses to Fastly

### Request Types

The Lambda function handles two types of requests:

1. **Health Check Requests**: Fastly periodically sends requests to `/.well-known/fastly/logging/challenge` to verify the endpoint is working
   - The function calculates a SHA256 hash of the service_id and returns it as plain text
   - This is required by Fastly to validate the endpoint

2. **Log Forwarding Requests**: Fastly sends log data via POST to the configured endpoint
   - The function extracts the log data from the request body
   - Handles base64 encoding and gzip compression
   - Forwards the logs to Logz.io using the provided token and host

### Error Handling

- The function implements a retry mechanism for transient failures
- It masks sensitive data (like tokens) in logs
- All errors are logged to CloudWatch for monitoring
- Even on downstream errors, the function returns 200 to Fastly to prevent retry storms

## Release Process

This project uses GitHub Actions to automate the release process. When a new release is published on GitHub, the Lambda function is automatically deployed to AWS.

### Creating a New Release

1. Create a new release on GitHub with a version number tag (e.g., "1.0.1")
2. The release workflow will automatically:
   - Update the version.py file with the release tag version
   - Package the Lambda function
   - Deploy it to AWS Lambda
   - Update the function configuration

### Required GitHub Secrets

The following secrets need to be configured in your GitHub repository:

- `AWS_ACCESS_KEY_ID`: AWS access key with permissions to update Lambda
- `AWS_SECRET_ACCESS_KEY`: AWS secret key

### Required GitHub Variables

The following variables need to be configured in your GitHub repository:

- `AWS_REGION`: AWS region where your Lambda is deployed
- `AWS_LAMBDA_FUNCTION_NAME`: Name of your Lambda function

## Setup and Deployment

### Lambda Setup

1. Create a new Python 3.11+ Lambda function
2. Upload the `lambda_function.py` and `version.py` files
3. No environment variables required as all configuration is via query parameters
4. Set the Lambda timeout to at least 30 seconds
5. Set the memory allocation based on your log volume (128MB is usually sufficient)

### API Gateway Configuration

1. Create a new HTTP API in API Gateway
2. Create the following routes:
   - `GET /.well-known/fastly/logging/challenge` → Lambda integration
   - `POST /logs` → Lambda integration
3. Ensure query string parameters are passed to the Lambda
4. Deploy the API to a stage (e.g., `prod`)

### IAM Role Configuration

The Lambda function requires an IAM role with the following policies:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

## Monitoring and Troubleshooting

- Monitor the Lambda function's CloudWatch Logs for execution details and errors
- Debug Mode: To enable detailed debug logging, add `debug=true` to your query parameters
- Debug logs are prefixed with `🔍 DEBUG 🔍` for easy visibility
- Logs include the service ID for easy filtering
- Check CloudWatch Metrics for Lambda execution time, memory usage, and error rates

## Development Notes

### Running Tests Locally

To run tests locally:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest
pytest --cov=. --cov-report=term
deactivate
```

## Changelog

- **1.0.0**
   - Initial release
   - Support for Fastly health check mechanism
   - Log forwarding to Logz.io
   - Support for gzipped and uncompressed logs

   - Debug mode
   - Retry mechanism for transient failures 