#!/usr/bin/env python 
'''
Project£º WebCrawler 
Author: @Yifan Zhang(zhang.yifan@husky.neu.edu)   001616011
Date: 02/01/2016
'''
import socket 
import sys 
import xml
import mimetools
import base64
import urlparse
import re
import time
import Queue

#variable declaration 
defaultHostName = "cs5700sp16.ccs.neu.edu"
defaultPort = 80
defaultUsername = "001616011"
defaultPasswd = "SYKW5ID2"
defaultUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0"
defaultAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
defaultHttpHeaderHost = "cs5700sp16.ccs.neu.edu"
defaultLanguage = "en-US,en;q=0.5"
defaultEncoding = "gzip, deflate"
defaultConnection = "keep-alive"
defaultHeaderBodayDelimiter = "\r\n\r\n" # double blank rows
defaultLoginUrl = "http://cs5700sp16.ccs.neu.edu/accounts/login/?next=/fakebook/"
defaultBaseURL = "http://cs5700sp16.ccs.neu.edu/fakebook/"
rootCrawlPage = "/fakebook/"
secretFlagPattern = "<h2 class=\'secret_flag\' style=\"color:red\">FLAG: ([a-zA-Z0-9]{64})</h2>"
secretFlags = [ ] 

httpRequestHeaders = [ ] 

#function utility    
def basicRequestHeaderCompose(_method, _path, _host,_usrAgent, _accept, _acceptLanguage, _acceptEncoding,_connection):
    # used to compose basic HTTP 1.1 required attributes, this not contains cache and username and password 
    requestHeaders = [
        "%s %s HTTP/1.1\r\n" % (_method, _path),
        "Host: %s\r\n" % _host,
        "User-Agent: %s\r\n" %_usrAgent,
        "Accept: %s\r\n" %_accept,
        "Accept-Language: %s\r\n" % _acceptLanguage,
       "Referer: http://cs5700sp16.ccs.neu.edu/accounts/login/?next=/fakebook/\r\n",
       "Connection: %s\r\n" % _connection,        
    ]
    return requestHeaders

def cvtStrListToString(_lists):
    httpRequest = ""    
    for _list in _lists:
        httpRequest += _list
    return httpRequest

def extractSecretFlags(_responseHtmlBody, _flagPattern):
    #extract the specific Secret Flags in pages
    if _responseHtmlBody and _flagPattern:        
        flagPattern = re.compile(_flagPattern)
        flags = re.findall(flagPattern,_responseHtmlBody)
        if flags:
            return (True,flags)
        else:
            return (False, None)
    return (False, None)
 
def extractPageURLs(_responseHtmlBody):
    #extract all the URLs within the page
    urlPatternStr = "<a href=\"/fakebook/(.*?)\">"
    urlPattern = re.compile(urlPatternStr)
    urls = re.findall(urlPattern,_responseHtmlBody)
    return urls

def extractTokenFromHeader(_response, _delimiter):
    # this function used to extract crs token
    if not _response:
        return -1
    httpHeader =  responseHeaderSpliter(_response,_delimiter)
    csrfTokenPattern = "Set-Cookie: csrftoken=[a-f0-9]{32}"
    tokenPattern = re.compile(csrfTokenPattern)
    token = re.findall(tokenPattern,httpHeader)
    tokenID = token[0].split('=')[1]
    return tokenID
     

def extractSessionIdFromHeader(_response, _delimiter):
    # extract session ID from the current  httpheader
    if not _response:
        return -1
    httpHeader = responseHeaderSpliter(_response,_delimiter)
    sessionidPatternStr = "Set-Cookie: sessionid=[a-f0-9]{32}"
    sessionidPattern = re.compile(sessionidPatternStr)
    session = re.findall(sessionidPattern,httpHeader)
    sessionID = session[0].split("=")[1]
    return sessionID
    

def extractHttpResponseStatusCode(_responseHeader):
    # extract the http error code from http header    
    tagLines = _responseHeader.split('\n')
    errorCode = tagLines[0].split(' ')[1]
    return errorCode
def getResponse(_sock, _url, _initialFlag = False,_token = None, _session = None):
    # this function will get inital response from server and get token    
    urlStr = urlparse.urlparse(_url)
    host = urlStr.netloc
    if not urlStr:
        path = "/"
    path = urlStr.path 
    
    httpResponse = basicRequestHeaderCompose("GET", path, host, defaultUserAgent, 
                                            defaultAccept, 
                                            defaultLanguage, 
                                            defaultEncoding, 
                                            defaultConnection)
    if not _initialFlag:        
        httpResponse.append("Cookie: csrftoken=%s; sessionid=%s" % (_token,_session))
        
    httpResponseStr = cvtStrListToString(httpResponse)+ "\r\n\r\n"
    _sock = socketCreation(defaultHostName,defaultPort)
    responseResult = sockectSend(_sock, httpResponseStr) 
   
    return responseResult
    
def sockectSend(_sock, _sendMsg):
    # this function used to send socket and get response
    _sock.send(_sendMsg)   
    response = ""
    #while True:
    data = _sock.recv(4096)
        #if not data:
            #break
    response = data
    _sock.close()
    return response

def socketCreation(_hostname,_port):
    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((_hostname,_port))
    return sock

def responseHeaderSpliter(_response, _delimiterFmt):
    #Split HTTP response header and HTML body
    http_header, delimiter, http_body = _response.partition(_delimiterFmt)
    return http_header

def responseBodySpliter(_response,_delimiterFmt):
    #Split HTTP response header/body
    http_header, delimiter, http_body = _response.partition(_delimiterFmt)
    return http_body 
def postLoginInformation(_url,_username,_passwd,_crsftoken, _sessionid):
    # this function used to post login Information
    postData = "username=%s&password=%s&csrfmiddlewaretoken=%s&next=" % (_username,_passwd,_crsftoken) 
    httpRequestMsgs = basicRequestHeaderCompose("POST", urlparse.urlparse(_url).path, defaultHttpHeaderHost,defaultUserAgent,defaultAccept,defaultLanguage,defaultEncoding,defaultConnection)
    httpRequestMsgs.append("Cookie: csrftoken=%s; sessionid=%s\r\n" % (_crsftoken,_sessionid))
    httpRequestMsgs.append("Content-Type: application/x-www-form-urlencoded\r\n")
    httpRequestMsgs.append("Content-Length: " + str(len(postData)))
    httpRequestStr = cvtStrListToString(httpRequestMsgs) + "\r\n\r\n"
     
    httpRequest = httpRequestStr + postData      
   
    _sock = socketCreation(defaultHostName,defaultPort)
    
    response = sockectSend(_sock, httpRequest)
    
    return response

def login(_sock,_url, _delimiter,_username,_passwd):
    # this function used to perform login process    
    resp = getResponse(_sock, _url,True)
    if not resp:
        print ("response is not found! \n")
       
    token = extractTokenFromHeader(resp,_delimiter)
    if token != -1:
        CSRFToken = token
    else:
        print ("No Tokens found!\n")
    session = extractSessionIdFromHeader(resp,_delimiter)
    if session != -1:
        sessionid = session
    else:
        print ("sessionid not found!\n")
    
    loginResponse = postLoginInformation( _url, _username, _passwd, CSRFToken, sessionid)
    sock2 = socketCreation(defaultHostName,defaultPort)
    if is302Redirect(loginResponse,_delimiter):
        header = responseHeaderSpliter(loginResponse,_delimiter)
        cookieFlag = isCookieChanged(header)
        if cookieFlag:
            session = extractSessionIdFromHeader(loginResponse, _delimiter)
            if isTokenChanged(header):
                CSRFToken = extractTokenFromHeader(loginResponse,_delimiter)
            response = getResponse(sock2, "http://cs5700sp16.ccs.neu.edu/fakebook/", False,CSRFToken,session)
        else:
            response = getResponse(sock2, "http://cs5700sp16.ccs.neu.edu/fakebook/",False,CSRFToken,session)
        return (True,response,CSRFToken,session)
    else:
        return (False, "",CSRFToken,sesstion) 
                   
def isCookieChanged(_responseHeader):
    #Judge whether the authentication is already been cached
    if "Set-Cookie:" in _responseHeader:
        return True
    return False

def isTokenChanged(_responseHeader):
    # judge whether token changes
    if "csrftoken" in _responseHeader:
        return True
    return False
def is302Redirect(_response,_delimiter):
    # if 302, need to redirect to other webpages
    if not _response:
        return False
    header = responseHeaderSpliter(_response,_delimiter)
    statusCode = extractHttpResponseStatusCode(header)
    if statusCode.startswith("3"):
        return True
    return False
def is500ServerError(_response, _delimiter):
    if  _response:
        header = responseBodySpliter(_response, _delimiter)
        statusCode = extractHttpResponseStatusCode(header)
    if statusCode.startswith("5"):
        return True
    return False
def crawl(_sock,resp, token,sessionid,_flagPattern,_delimiter):
    #crawl webpage
    body = responseBodySpliter(resp, _delimiter)
    flagExistence, flags = extractSecretFlags(body, _flagPattern)
    if flagExistence:
        for flag in flags:
            secretFlags.append(flag)
            
    urlsNeedVisit = Queue.Queue()
    urlsAlreadyVisited = []
    urlsNeedVisit.put("")
    urlsAlreadyVisited.append("http://cs5700sp16.ccs.neu.edu/fakebook/")
    urls = extractPageURLs(body)
    
    while (urlsNeedVisit.empty() == False):
        for url in urls:
            if url not in urlsAlreadyVisited:
                if url:
                    urlsNeedVisit.put(defaultBaseURL + url)
                else:
                    pass
        URL = urlsNeedVisit.get()
        #urlsAlreadyVisited.append(URL)
        if URL in urlsAlreadyVisited:
            continue
        response = getResponse(_sock, URL , False, token, sessionid)
        #if is500ServerError(response, _delimiter):
            #continue
        urlsAlreadyVisited.append(URL)
        responsebody = responseBodySpliter(response, _delimiter)
        
        urls = extractPageURLs(responsebody)
        
        if responsebody.find("FLAG") != -1:
            existence, secret_flags = extractSecretFlags(responsebody,_flagPattern)
            if existence:
                if secret_flags not in secretFlags:
                    secretFlags.append(secret_flags)
            
        print ("the length is: %d" % len(secretFlags))
        if len(secretFlags) > 4:
            break

def main(argv):
    if argv:
        username = argv[-2]
        password = argv[-1]
    else:
        username = defaultUsername
        password = defaultPasswd
    username 
    sock = socketCreation(defaultHostName,defaultPort)
    logined, resp, token, sessionid = login(sock, defaultLoginUrl, defaultHeaderBodayDelimiter, username, password)
    
    while not logined:
        logined, resp, token, sessionid = login(sock, defaultLoginUrl, defaultHeaderBodayDelimiter, username, password)
        
    crawl(sock,resp,token,sessionid,secretFlagPattern,defaultHeaderBodayDelimiter)
    flagResults = ""
    for flag in secretFlags:
        flagResults += str(flag) + "\r\n"
 
    flagpatternstr = "\[\'([a-z0-9A-z]{64})\']"
    flagpattern = re.compile(flagpatternstr)
    values = re.findall(flagpattern,flagResults)
    secrectValues = ""
    for value in values:
        secrectValues += value + "\r\n"
    print secrectValues    
if __name__ == "__main__":
    main(sys.argv[1:])