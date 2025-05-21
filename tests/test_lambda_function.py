import json
import unittest
from unittest.mock import patch, MagicMock, ANY

import lambda_function
from version import __version__


class TestLambdaFunction(unittest.TestCase):

    def setUp(self):
        self.sample_query_params = {
            'service_id': 'test-service-id',
            'token': 'test-token',
            'host': 'test-host.logz.io',
            'type': 'test-logs',
            'debug': 'true'
        }
        
        self.sample_event = {
            'queryStringParameters': self.sample_query_params,
            'rawQueryString': 'service_id=test-service-id&token=test-token&host=test-host.logz.io&type=test-logs&debug=true',
            'requestContext': {
                'http': {
                    'method': 'POST'
                }
            },
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'test': 'data'}),
            'isBase64Encoded': False,
            'rawPath': '/logs'
        }
        
        self.health_check_event = {
            'queryStringParameters': self.sample_query_params,
            'rawQueryString': 'service_id=test-service-id&token=test-token&host=test-host.logz.io',
            'requestContext': {
                'http': {
                    'method': 'GET'
                }
            },
            'rawPath': '/.well-known/fastly/logging/challenge'
        }

    def test_get_user_config_with_valid_params(self):
        config = lambda_function.get_user_config(self.sample_query_params)
        
        self.assertEqual(config['fastly_service_id'], 'test-service-id')
        self.assertEqual(config['logzio_token'], 'test-token')
        self.assertEqual(config['logzio_listener_host'], 'test-host.logz.io')
        self.assertEqual(config['logzio_type'], 'test-logs')
        self.assertTrue(config['debug'])

    def test_get_user_config_with_missing_params(self):
        with self.assertRaises(lambda_function.ConfigurationError):
            lambda_function.get_user_config({})

    def test_calculate_sha256_hash(self):
        service_id = 'test-id'
        expected_hash = '6cc41d5ec590ab78cccecf81ef167d418c309a4598e8e45fef78039f7d9aa9fe\n'
        result = lambda_function.calculate_sha256_hash(service_id)
        self.assertEqual(result, expected_hash)

    def test_get_logzio_url(self):
        config = {
            'logzio_listener_host': 'test-host.logz.io',
            'logzio_token': 'test-token',
            'logzio_type': 'test-logs'
        }
        expected_url = f"https://test-host.logz.io:{lambda_function.LOGZIO_PORT}?token=test-token&type=test-logs"
        result = lambda_function.get_logzio_url(config)
        self.assertEqual(result, expected_url)

    @patch('lambda_function.urllib.request.Request')
    @patch('lambda_function.urllib.request.urlopen')
    def test_forward_to_logzio_success(self, mock_urlopen, mock_request):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'Success'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        config = {
            'logzio_listener_host': 'test-host.logz.io',
            'logzio_token': 'test-token',
            'logzio_type': 'test-logs'
        }
        
        status, response = lambda_function.forward_to_logzio('test data', False, config)
        
        self.assertEqual(status, 200)
        self.assertEqual(response, 'Success')
        mock_request.assert_called_once()
        self.assertEqual(mock_request.call_args[1]['headers']['User-Agent'], f"fastly-logs-{__version__}")

    @patch('lambda_function.urllib.request.Request')
    @patch('lambda_function.urllib.request.urlopen')
    @patch('time.sleep')
    def test_forward_to_logzio_retry(self, mock_sleep, mock_urlopen, mock_request):
        # First call raises 503 error
        mock_error_response = MagicMock()
        mock_error_response.code = 503
        mock_error_response.read.return_value = b'Server Error'
        
        # Create a successful response for the second attempt
        mock_success_response = MagicMock()
        mock_success_response.status = 200
        mock_success_response.read.return_value = b'Success'
        mock_success_response.__enter__.return_value = mock_success_response
        
        # Configure urlopen to first raise an error, then return success
        mock_urlopen.side_effect = [
            lambda_function.urllib.error.HTTPError(
                'url', 503, 'Service Unavailable', {}, None
            ),
            mock_success_response
        ]
        
        config = {
            'logzio_listener_host': 'test-host.logz.io',
            'logzio_token': 'test-token',
            'logzio_type': 'test-logs'
        }
        
        status, response = lambda_function.forward_to_logzio('test data', False, config)
        
        self.assertEqual(status, 200)
        self.assertEqual(response, 'Success')
        self.assertEqual(mock_request.call_count, 2)
        mock_sleep.assert_called_once_with(lambda_function.RETRY_DELAY_SECONDS)

    @patch('lambda_function.handle_health_check')
    def test_lambda_handler_health_check(self, mock_health_check):
        mock_health_check.return_value = {'statusCode': 200}
        
        result = lambda_function.lambda_handler(self.health_check_event, {})
        
        mock_health_check.assert_called_once_with(self.sample_query_params)
        self.assertEqual(result, {'statusCode': 200})

    @patch('lambda_function.handle_logs')
    def test_lambda_handler_log_forwarding(self, mock_handle_logs):
        mock_handle_logs.return_value = {'statusCode': 200}
        
        result = lambda_function.lambda_handler(self.sample_event, {})
        
        mock_handle_logs.assert_called_once_with(self.sample_event, self.sample_query_params)
        self.assertEqual(result, {'statusCode': 200})

    @patch('lambda_function.forward_to_logzio')
    def test_handle_logs_success(self, mock_forward):
        mock_forward.return_value = (200, 'Success')
        
        result = lambda_function.handle_logs(self.sample_event, self.sample_query_params)
        
        self.assertEqual(result['statusCode'], 200)
        mock_forward.assert_called_once()

    def test_handle_health_check_success(self):
        result = lambda_function.handle_health_check(self.sample_query_params)
        
        self.assertEqual(result['statusCode'], 200)
        self.assertIn('Content-Type', result['headers'])
        self.assertTrue(result['body'])  # Should contain SHA256 hash

    def test_handle_health_check_error(self):
        result = lambda_function.handle_health_check({})
        
        self.assertEqual(result['statusCode'], 400)
        self.assertIn('Configuration error', result['body'])


if __name__ == '__main__':
    unittest.main() 