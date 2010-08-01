"""
Tests are good.
"""

import unittest
import goldengate.http


class StartResponse(object):
    status = None
    headers = None
    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


class HttpTests(unittest.TestCase):
    requests = [
        ({'PATH_INFO': '/', 'REQUEST_METHOD': 'POST'}, {'path': '/', 'query': None, 'relative_uri': '/', 'method': 'post'}),
        ({'PATH_INFO': '/', 'QUERY_STRING': '', 'REQUEST_METHOD': 'POST'}, {'path': '/', 'query': '', 'relative_uri': '/?', 'method': 'post', 'headers': {}}),
    ]

    def test_request(self):
        for environ, attributes in self.requests:
            request = goldengate.http.Request(environ, lambda *args, **kwargs: None)
            for attribute, expected in attributes.iteritems():
                self.assertEquals(getattr(request, attribute), expected)

    def test_response(self):
        output = '{"name": "snarf"}'
        headers = [('favorite-vegetable', 'asparagus')]
        start_response = StartResponse()

        response = goldengate.http.Response(output, headers=headers)
        self.assertEquals(response.send(start_response), output)
        self.assertEquals(start_response.status, '200 OK')

        headers.append(('content-type', '%s; charset=utf-8' % (response.content_type,)))
        self.assertEquals(len(start_response.headers), len(headers))
        for name, value in headers:
            self.assertEquals(start_response.headers[name], value)
            

if __name__ == '__main__':
    unittest.main()
