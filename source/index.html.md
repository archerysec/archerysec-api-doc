---
title: Archery API Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - shell


toc_footers:
  - <a href='https://github.com/anandtiwarics/archerysec/'>Sign Up for a Contribution</a>
  - <a href='https://github.com/lord/slate'>Documentation Powered by Slate</a>

includes:
  - errors

search: true
---

# Introduction

```shell
                    _                     
     /\            | |                    
    /  \   _ __ ___| |__   ___ _ __ _   _ 
   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
  / ____ \| | | (__| | | |  __/ |  | |_| |
 /_/    \_\_|  \___|_| |_|\___|_|   \__, |
                                     __/ |
                                    |___/ 
 
```

Welcome to the Archery Tool API! You can use our API to access Archery Tool API endpoints, which can help you to launch scan and manage vulnerabilities.

The API is organized around REST. All request and response bodies, including errors, are encoded in JSON.


To play around with a few examples, we recommend a REST client called Postman. Simply tap the button below to import a pre-made collection of examples.

[![Run in Postman](https://run.pstmn.io/button.svg)](https://www.getpostman.com/collections/:collection_id?)


### Note

Archery tool and Documentation is still **in-progress**. When i have free-time, i will improve documentation.

# Authentication

> To authorize, use this code:

```shell
# With shell, you can just pass the correct header with each request

curl http://localhost:8000/api-token-auth/ \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin@123"}' 
  
```

> The above command returns JSON structured like this:

```json
[
  {
    "token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    .eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl9pZCI6MSwiZW1haW
    wiOiIiLCJleHAiOjE1MTU4NzQxNDR9.3Oy0ga2jp3
    A8Pjh0T87LZijBh-M94z-mgjZ06j-mI0w"
  }
]

```

Provide your Archery tool credential in order to get the authentication token which will use for all further API calls. 


### Query Parameters

Parameter | Required| Description
--------- | ------- | -------------------|
`username`  | Yes |Provide your username.  
`password` | Yes |Provide your password.


# Projects

## Get All Projects


```shell
curl http://localhost:8000/api/project/ \
  -H "Content-Type: application/json" \
  -H "Authorization: JWT token"
```

> The above command returns JSON structured like this:

```json

[
  {
    "project_id":"cf8ca247-dde3-445c-bfee-07366d7c6136",
    "project_name":"ASDF",
    "project_disc":"ASD",
    "project_start":"2018-01-11",
    "project_end":"2018-01-09",
    "project_owner":"SDF"
  }
]

```

Get the list of all projects and create projects using API. Archery tool has the ability to manage your projects and their scans. We can create projects bin where we are performing scans.

Use the project list API to get the all available projects in Archery Tool.


Now in order to access protected api urls you must include the `Authorization: JWT <your_token>` header.

<aside class="notice">
You must replace <code>Token</code> with your personal API token.
</aside>


## Create Project

```shell

curl http://localhost:8000/api/project/ \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: JWT token" \
    -d '{"project_name":"ASDF",
          "project_disc":"ASD",
          "project_start":"2018-01-11",
          "project_end":"2018-01-09",
          "project_owner":"SDF"}'

```


> The above command returns JSON structured like this:

```json
[
  {
    "message":"Project Created"
  }
]
```


Create a new project for an account. Project name and project description is required field to create new project. Others are optional and may you leave empty.


### Query Parameters

Parameter | Required| Description
--------- | ------- | -------------------|
project_name | Yes |Provide the project Name. Archery including all projects name is required to create new porject.
project_disc | Yes |Project Description. Provide proper descriptions about the project for understanding
project_start | Optional | Project start date. This parameter is optional.
project_end | Optional | Project end date. This parameter is optional
project_owner | Optional | Tag a Owner of the project. This Parameter is optional.


# Web Scan

## Get All Web Scans


```shell
curl http://localhost:8000/api/webscan/ \
  -H "Content-Type: application/json" \
  -H "Authorization: JWT token"
```


> The above command returns JSON structured like this:

```json
[
    {
        "scan_url": "http://demo.testfire.net",
        "project_id": "93a102fe-0d16-465b-b487-f331af1bfb9b",
        "scan_scanid": "4f47616d-2b97-4ba2-a483-1a963de7e6c3",
        "vul_status": 100,
        "total_vul": "230",
        "high_vul": "5",
        "medium_vul": "60",
        "low_vul": "165",
        "date_created": "2018-01-11T09:01:11.851000Z",
        "date_modified": "2018-01-11T09:01:11.858000Z"
    },
    {
        "scan_url": "http://demo.testfire.net",
        "project_id": "93a102fe-0d16-465b-b487-f331af1bfb9b",
        "scan_scanid": "23ac9336-42f4-4752-a2b1-5ac73a1d9af4",
        "vul_status": 100,
        "total_vul": "230",
        "high_vul": "5",
        "medium_vul": "61",
        "low_vul": "164",
        "date_created": "2018-01-11T09:01:11.851000Z",
        "date_modified": "2018-01-11T09:01:11.858000Z"
    }
]
```

This endpoint retrieves all webscans results. Archery performing webscans and if you want to list down all available scans, you can use this API. This is simple HTTP get request which list down all your web scans. 

### HTTP Request

`GET http://localhost:8000/api/webscan/`



<!-- <aside class="success">
authenticated
</aside> -->

## Launch Web Scan


```shell
curl http://localhost:8000/api/webscan/ \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: JWT token" \
    -d '{"scan_url":"http://example.com","project_id":"project_id","scanner":"zap_scan"}'
  
```


> The above command returns JSON structured like this:

```json
[
  {
    "message":"Scan Launched"
  }
]
```

The API endpoint use for Launch the scans. You can provide all required input and scan will be launched.

<!-- <aside class="warning">Inside HTML code blocks like this one, you can't use Markdown, so use <code>&lt;code&gt;</code> blocks to denote code.</aside> -->

### HTTP Request

`POST http://localhost:8000/api/webscan/`

### URL Parameters

Parameter | Required| Description
--------- | -----------| ------
scan_url | Yes | Provide the scan target URL 
project_id | Yes | Provide Project ID 
scanner | Yes | Provide scanner 
        |     |                 OWASP ZAP Scanner - zap_scan
        |     |                 Burp Scanner - burp_scan
        |     |                 Arachni - arachni

## Get Scan Results

```shell

curl http://localhost:8000/api/webscanresult/ \
    -X GET \
    -H "Content-Type: application/json" \
    -H "Authorization: JWT token" \
    -d '{"scan_id":"a20b9c2e-1bd0-4a69-8771-67c023a3b96b"}'

```

> The above command returns JSON structured like this:

```json

[
    {
        "scan_id": "6706074e-9fb9-48b8-96f9-b2500eba7bff",
        "project_id": "4cdf22f5-2edd-4615-8290-bbfcc06421e2",
        "url": "http://127.0.0.1:8008/webscanners/",
        "vuln_id": "e4f0091c-2bc7-4e7a-bd07-47b68f0f51f3",
        "confidence": "Medium",
        "wascid": "0",
        "cweid": "0",
        "risk": "Informational",
        "reference": "https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet",
        "name": "User Agent Fuzzer",
        "solution": "",
        "param": "Header User-Agent",
        "evidence": "",
        "sourceid": "1",
        "pluginId": "10104",
        "other": "",
        "attack": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "messageId": "297",
        "method": "GET",
        "alert": "User Agent Fuzzer",
        "ids": "",
        "description": "Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.",
        "req_res": "",
        "note": "",
        "rtt": "5",
        "tags": "[]",
        "timestamp": "1517461799789",
        "responseHeader": "HTTP/1.0 200 OK\r\nDate: Thu, 01 Feb 2018 05:09:59 GMT\r\nServer: WSGIServer/0.1 Python/2.7.13\r\nVary: Cookie\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2630\r\nSet-Cookie: csrftoken=15coi19x5Tb4QklEg614BhFRUKOgvb2dMStqmUOc6c2yLlMsJ2e29lFr5GKgmP4a; expires=Thu, 31-Jan-2019 05:09:59 GMT; Max-Age=31449600; Path=/\r\n\r\n",
        "requestBody": "",
        "responseBody": "<!DOCTYPE html>\n<html lang=\"en\">\n\n<head>\n    <title>Archery</title>\n    <link rel=\"icon\" href=\"/static/logo.png\" type=\"image/x-icon\">\n    <meta charset=\"UTF-8\"/>\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>\n    <link rel=\"stylesheet\" href=\"/static/css/bootstrap.min.css\"/>\n    <link rel=\"stylesheet\" href=\"/static/css/bootstrap-responsive.min.css\"/>\n    <link rel=\"stylesheet\" href=\"/static/css/archery-login.css\"/>\n    <link href=\"/static/font-awesome/css/font-awesome.css\" rel=\"stylesheet\"/>\n    <link href='http://fonts.googleapis.com/css?family=Open+Sans:400,700,800' rel='stylesheet' type='text/css'>\n\n</head>\n<body>\n<div id=\"loginbox\">\n    <form id=\"loginform\" class=\"form-vertical\" action=\"/auth/\" method=\"POST\"><input type='hidden' name='csrfmiddlewaretoken' value='ZbUNJtjW8leoWQxYIvt1vzIqDygVFRw6KYbPNmYB9E5SRRYMbrGZ3DI0OucVwvy3' />\n        <div class=\"control-group normal_text\"><h3><img src=\"/static/archery.png\"\n                                                        style=\"max-width:190px; margin-top: 10px;\" alt=\"\"/></h3></div>\n        <div class=\"control-group\">\n            <div class=\"controls\">\n                <div class=\"main_input_box\">\n                    <span class=\"add-on bg_lg\"><i class=\"icon-user\"> </i></span><input type=\"text\" name=\"username\"\n                                                                                       id=\"username\" tabindex=\"1\"\n                                                                                       class=\"form-control\"\n                                                                                       placeholder=\"Username\" value=\"\">\n                </div>\n            </div>\n        </div>\n        <div class=\"control-group\">\n            <div class=\"controls\">\n                <div class=\"main_input_box\">\n                    <span class=\"add-on bg_ly\"><i class=\"icon-lock\"></i></span><input type=\"password\" name=\"password\"\n                                                                                      id=\"password\" tabindex=\"2\"\n                                                                                      class=\"form-control\"\n                                                                                      placeholder=\"Password\">\n                </div>\n            </div>\n        </div>\n        <div class=\"form-actions\">\n\n            <span class=\"pull-right\"><button class=\"btn btn-lg btn-primary \" type=\"submit\">Sign in</button></span>\n        </div>\n    </form>\n</div>\n\n<script src=\"/static/js/jquery.min.js\"></script>\n<script src=\"/static/js/archery.login.js\"></script>\n</body>\n\n</html>\n",
        "requestHeader": "GET http://127.0.0.1:8008/webscanners/ HTTP/1.1\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nContent-Length: 0\r\nCookie: _sm_au_c=iVVTtWtfRrV5RSSs13;JSESSIONID=4B9D9690;\r\nHost: 127.0.0.1:8008\r\n\r\n",
        "cookieParams": "_sm_au_c=iVVTtWtfRrV5RSSs13;JSESSIONID=4B9D9690;csrftoken=15coi19x5Tb4QklEg614BhFRUKOgvb2dMStqmUOc6c2yLlMsJ2e29lFr5GKgmP4a; expires=Thu, 31-Jan-2019 05:09:59 GMT; Max-Age=31449600; Path=/",
        "res_type": "3",
        "res_id": "297",
        "date_time": null
    }
]


```


This endpoint retrieves vulnerability data for particular web scan. Archery performing web scan and if you want to list down all scan results of particular scan, you can use this API. This is simple HTTP post request which list down all your web scans data. 

### HTTP Request

`GET http://localhost:8000/api/webscanresult/`

### URL Parameters

Parameter | Required| Description
--------- | -----------| ------
scan_id | Yes | Provide the scan ID 


# Network Scans


## Get All Network Scans

```shell

curl "http://localhost:8000/api/networkscan/" \
  -H "Content-Type: application/json" \
  -H "Authorization: JWT token"

```

> The above command returns JSON structured like this:

```json
[
    {
        "scan_ip": "192.168.222.131",
        "project_id": "",
        "target_id": "c277f6e8-48ac-4245-bd66-6091d0f49d63",
        "scan_id": "6e0266f2-49af-49ab-917e-b8302a0bddc7",
        "scan_status": "100",
        "total_vul": "2365",
        "high_total": "344",
        "medium_total": "528",
        "low_total": "31",
        "date_created": "2018-01-11T09:01:11.269000Z",
        "date_modified": "2018-01-11T09:01:11.283000Z"
    },
    {
        "scan_ip": "192.168.222.131",
        "project_id": "93a102fe-0d16-465b-b487-f331af1bfb9b",
        "target_id": "e082a24e-5a95-43d1-bf13-1305c1c94e4e",
        "scan_id": "8aac9e08-7069-45f0-b7f3-491a3b667e6c",
        "scan_status": "100",
        "total_vul": "307",
        "high_total": "40",
        "medium_total": "67",
        "low_total": "5",
        "date_created": "2018-01-11T09:01:11.269000Z",
        "date_modified": "2018-01-11T09:01:11.283000Z"
    }
]


```


This endpoint retrieves all network scan results. Archery performing network and if you want to list down all available scans, you can use this API. This is simple HTTP get request which list down all your network scans. 

### HTTP Request

`GET http://localhost:8000/api/networkscan/`

## Scan Launch  

```shell

curl http://localhost:8000/api/networkscan/ \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: JWT token" \
    -d '{"scan_ip":"192.168.1.1","project_id":"project_id"}'

```

> The above command returns JSON structured like this:

```json

[
  {
    "message":"Scan Launched"
  }
]

```

The API endpoint use for Launch the scans. You can provide all required input and scan will be launched.

<!-- <aside class="warning">Inside HTML code blocks like this one, you can't use Markdown, so use <code>&lt;code&gt;</code> blocks to denote code.</aside> -->

### HTTP Request

`POST http://localhost:8000/api/networkscan/`

### URL Parameters

Parameter | Required| Description
--------- | -----------| ------
scan_ip | Yes | Provide the scan target IP 
project_id | Yes | Provide Project ID 

## Get Scan Results

```shell

curl http://localhost:8000/api/networkscanresult/ \
    -X GET \
    -H "Content-Type: application/json" \
    -H "Authorization: JWT token" \
    -d '{"scan_id":"a20b9c2e-1bd0-4a69-8771-67c023a3b96b"}'

```

> The above command returns JSON structured like this:

```json

[
    {
        "scan_id": "a20b9c2e-1bd0-4a69-8771-67c023a3b96b",
        "vul_id": "2a2b3c7a-f1cf-409c-8baf-d8d950cbab1f",
        "name": "'fckeditor' Connectors Arbitrary File Upload Vulnerability",
        "owner": "",
        "comment": "",
        "creation_time": "2018-01-05T15:35:03Z",
        "modification_time": "2018-01-05T15:35:03Z",
        "user_tags": "",
        "host": "192.168.222.133",
        "port": "general/tcp",
        "nvt": "",
        "scan_nvt_version": "",
        "threat": "Error",
        "severity": "-3.0",
        "qod": "",
        "description": "NVT timed out after 600 seconds.",
        "term": "",
        "keywords": "",
        "field": "",
        "filtered": "",
        "page": "",
        "vuln_color": "",
        "family": "Web application abuses",
        "cvss_base": "4.6",
        "cve": "NOCVE",
        "bid": "NOBID",
        "xref": "URL:http://www.fckeditor.net",
        "tags": "cvss_base_vector=AV:N/AC:H/Au:S/C:P/I:P/A:P|summary=Web applications providing a wrong configured 'fckeditor'\n  connectors might be prone to an arbitrary-file-upload vulnerability.|impact=An attacker may leverage this issue to upload arbitrary files to the\n  affected system\n this can result in arbitrary code execution within the context of the vulnerable application.|solution=Check the config.php of this connector and make sure that no arbitrary file\n  extensions are allowed for uploading.|solution_type=Workaround|qod_type=remote_analysis",
        "banner": "remote_analysis",
        "date_time": "2018-02-01 13:57:09.607000+00:00"
    },
    {
        "scan_id": "a20b9c2e-1bd0-4a69-8771-67c023a3b96b",
        "vul_id": "155584f4-c9f1-4e40-95f7-bb5d893a0743",
        "name": "/doc directory browsable",
        "owner": "",
        "comment": "",
        "creation_time": "2018-01-05T14:07:12Z",
        "modification_time": "2018-01-05T14:07:12Z",
        "user_tags": "",
        "host": "192.168.222.131",
        "port": "80/tcp",
        "nvt": "",
        "scan_nvt_version": "",
        "threat": "Medium",
        "severity": "5.0",
        "qod": "",
        "description": "Vulnerable url: http://192.168.222.131/doc/",
        "term": "",
        "keywords": "",
        "field": "",
        "filtered": "",
        "page": "",
        "vuln_color": "",
        "family": "Web application abuses",
        "cvss_base": "5.0",
        "cve": "CVE-1999-0678",
        "bid": "318",
        "xref": "NOXREF",
        "tags": "cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N|solution=Use access restrictions for the /doc directory.\n  If you use Apache you might use this in your access.conf:\n\n  <Directory /usr/doc>\n  AllowOverride None\n  order deny,allow\n  deny from all\n  allow from localhost\n  </Directory>|summary=The /doc directory is browsable.\n  /doc shows the content of the /usr/doc directory and therefore it shows which programs and - important! - the version of the installed programs.|solution_type=Mitigation|qod_type=remote_banner",
        "banner": "remote_banner",
        "date_time": "2018-02-01 13:57:09.646000+00:00"
    }
]


```


This endpoint retrieves vulnerability data for particular Network scan. Archery performing Network scan and if you want to list down all scan results of particular scan, you can use this API. This is simple HTTP post request which list down all your Network scans data. 

### HTTP Request

`GET http://localhost:8000/api/networkscanresult/`

### URL Parameters

Parameter | Required| Description
--------- | -----------| ------
scan_id | Yes | Provide the scan ID 

