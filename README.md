HeaderScan
==========

"HeaderScan" Burp Pro Plugin (http://portswigger.net/burp/extender/)

HedaerScan is a Burp Pro plugin that extends a scope of an automated web scan with some very promissing entry points. 

Short intro:
--------------

Certain web apps process particular HTTP headers, that aren't necessarily present in a typical Browser generated requests (especially when you are analyzing them form an unauthenticated surface).
From my proffesional experience I have already pwn'ed few applications with this approach, so I thought it would be good to automate this in some way. 

Extension:
--------------

So what does it do?

It takes every original HTTP request that goes into your Burp ActiveScan queue and automatically generates extra scanning tasks (with an additional header to fuzz).

As a result for every resource in your testing scope, you will let Burp addditionally scan values of the following headers (taken from HTTP RFC):

    {"X-Sfg-Data","Accept","Accept-Charset","Accept-Encoding",
        "Accept-Language","Accept-Datetime","Authorization",
        "Cache-Control","Connection","Cookie","Content-Length"
        ,"Content-MD5","Content-Type","Date" ,"Expect","From",
        "Host","If-Match","If-Modified-Since","If-None-Match",
        "If-Range","If-Unmodified-Since","Max-Forwards","Pragma",
        "Proxy-Authorization","Range","Referer","TE","Upgrade",
        "User-Agent","Via","Warning","X-Requested-With",
        "DNT","X-Forwarded-For","X-Forwarded-Proto",
        "Front-End-Https","x-att-deviceid","x-wap-profile",
        "Proxy-Connection"};

Features:
--------------

- It's written in Java, so you can try it without any additional setup.
- It will fuzz only Headers that aren't present in the original request (blind fuzzing)
- It will generate additional scan only once for every URI (excluding parameters).
- You can disable it (config tab) or just use send_to menu option :P
- No ads, and backdoors included. 

Example:
--------------

Lets say that we want to send to ActiveScan queue the following request:

### Original request:

    GET / HTTP/1.1
    Host: www.example.pl
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:26.0) Gecko/20100101 Firefox/26.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate


HeaderScan will generate additional active scan tasks (32 - for every header that isn't present in the original request).
Each scan will have a predefined scanning offset, so only header values are analyzed by Burp :

### Scan nr. 22

    GET / HTTP/1.1
    Host:www.example.pl
    User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv
    Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language:en-US,en;q=0.5
    Accept-Encoding:gzip, deflate
    Cookie:PREF=ID=cc48904a176c0c3f
    Connection:keep-alive
    If-Match:FUZZME


Only FUZZME will be fuzzed by Burp.


Usage:
--------------

Use either the compiled version in dist directory or use the whole project file in Netbeans.

