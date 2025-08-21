#!/bin/bash

# Script to generate test traffic through Burp proxy at localhost:8080
# This will create requests that should be captured by the Belch extension

echo "Generating test traffic through Burp proxy at localhost:8080..."

# Test various endpoints to create diverse traffic
PROXY="http://localhost:8080"

echo "Making requests to httpbin.org..."

# GET request
curl -x $PROXY -s "http://httpbin.org/get?test=value1&tag=api" > /dev/null

# POST request with JSON
curl -x $PROXY -s -X POST "http://httpbin.org/post" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "value": "example"}' > /dev/null

# PUT request
curl -x $PROXY -s -X PUT "http://httpbin.org/put" \
  -H "Content-Type: application/json" \
  -d '{"update": "data"}' > /dev/null

# DELETE request
curl -x $PROXY -s -X DELETE "http://httpbin.org/delete" > /dev/null

# Request with headers
curl -x $PROXY -s "http://httpbin.org/headers" \
  -H "X-Test-Header: value" \
  -H "User-Agent: BelchTester/1.0" > /dev/null

# Request with basic auth
curl -x $PROXY -s "http://httpbin.org/basic-auth/user/pass" \
  -u user:pass > /dev/null

# Form data
curl -x $PROXY -s -X POST "http://httpbin.org/form" \
  -d "field1=value1&field2=value2" > /dev/null

echo "Making requests to example.com..."

# Simple GET requests to example.com
curl -x $PROXY -s "http://example.com/" > /dev/null
curl -x $PROXY -s "http://example.com/test?param=1" > /dev/null
curl -x $PROXY -s "http://example.com/api/test" > /dev/null

echo "Making requests to jsonplaceholder.typicode.com..."

# API-style requests
curl -x $PROXY -s "https://jsonplaceholder.typicode.com/posts/1" > /dev/null
curl -x $PROXY -s "https://jsonplaceholder.typicode.com/users" > /dev/null

curl -x $PROXY -s -X POST "https://jsonplaceholder.typicode.com/posts" \
  -H "Content-Type: application/json" \
  -d '{"title": "test", "body": "content", "userId": 1}' > /dev/null

echo "Traffic generation complete!"
echo "Check the Belch API with: curl http://localhost:7850/proxy/stats"