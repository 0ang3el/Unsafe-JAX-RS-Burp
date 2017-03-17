try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import IHttpRequestResponse
    from burp import IScanIssue
    from burp import IParameter
    from burp import IScannerInsertionPointProvider
    from burp import IScannerInsertionPoint
    from array import array
    from random import *
    from string import *
    from re import *
    import StringIO
    import gzip
    from urlparse import urlparse
except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'
DEBUG = True        # Turn on/off debug info in console
callbacks = None
helpers = None

def debug2console(title, *args):
    if DEBUG:
        print "[ debug ]", "Begin", title
        for arg in args:
            print arg
        print "[ debug ]", "End", title 

def gzip_encode(str):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(str)
    return out.getvalue()

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
        
    return helpers.bytesToString(bytes)

def should_trigger_per_request_attacks(request_info, insertionPoint): ### Hack to make per-request scan from @albinowax
    params = request_info.getParameters()

    if params:
        first_parameter_offset = 999999
        first_parameter = None
        for param_type in (IParameter.PARAM_BODY, IParameter.PARAM_URL, IParameter.PARAM_JSON, IParameter.PARAM_XML,
                           IParameter.PARAM_XML_ATTR, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_COOKIE):
            for param in params:
                if param.getType() != param_type:
                    continue
                if param.getNameStart() < first_parameter_offset:
                    first_parameter_offset = param.getNameStart()
                    first_parameter = param
            if first_parameter:
                break

        if first_parameter and first_parameter.getName() == insertionPoint.getInsertionPointName():
            return True

    elif insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER and \
         insertionPoint.getInsertionPointName() == 'User-Agent':

        return True

    debug2console('Skiping insertion point', insertionPoint.getInsertionPointName())
    return False

def get_random_string(len):
    return "".join([choice(ascii_letters) for _ in range(len)])

def get_request_headers_as_dict(request):
    rawHeaders = helpers.analyzeRequest(request).getHeaders()
    return dict((header.split(':')[0], header.split(':', 1)[1].strip()) for header in rawHeaders[1:])


def get_response_headers_as_dict(response):
    rawHeaders = helpers.analyzeResponse(response).getHeaders()
    return dict((header.split(':')[0], header.split(':', 1)[1].strip()) for header in rawHeaders[1:])

def get_response_status_code(response):
    return helpers.analyzeResponse(response).getStatusCode();
    
def get_response_body(response):
    offset = helpers.analyzeResponse(response).getBodyOffset()
    return response[offset:]

def get_request_body(request):
    offset = helpers.analyzeRequest(request).getBodyOffset()
    return request[offset:]

# Add header or modify existing
def add_header_to_request(request, header_name, header_value):
    info = helpers.analyzeRequest(request)
    
    requestBodyOffset = info.getBodyOffset()
    requestHeaders = request[:requestBodyOffset].split('\r\n')
    requestBody = request[requestBodyOffset:]
    
    headerExists = len(filter( lambda x: header_name in x, requestHeaders )) > 0
    
    modifiedHeaders = ""
    
    if headerExists:
        modifiedHeaders = "\r\n".join([header if header_name not in header else header_name + header_value  for header in requestHeaders])
    else:
        modifiedHeaders = "\r\n".join([header if "Host: " not in header else header + "\r\n" + header_name + header_value  for header in requestHeaders])
    
    return modifiedHeaders + requestBody

def remove_header_from_request(request, header_name):
    info = helpers.analyzeRequest(request)
    
    requestBodyOffset = info.getBodyOffset()
    requestHeaders = request[:requestBodyOffset].split('\r\n')
    requestBody = request[requestBodyOffset:]
    
    headerExists = len(filter( lambda x: header_name in x, requestHeaders )) > 0
    
    if headerExists:
        modifiedHeaders = "\r\n".join([header for header in requestHeaders if header_name not in header])
        return modifiedHeaders + requestBody
    
    return request

def add_body_to_request(request, body):
    info = helpers.analyzeRequest(request)
    requestBodyOffset = info.getBodyOffset()
    requestHeaders = request[:requestBodyOffset]
    requestBody = request[requestBodyOffset:]
        
    h = helpers.stringToBytes(requestHeaders)
    b = helpers.stringToBytes(body)
    h.extend(b)
    
    return add_header_to_request(safe_bytes_to_string(h),"Content-Length: ",str(len(body)))

def prepare(basePair):
    request = safe_bytes_to_string(basePair.getRequest())
    response = basePair.getResponse()
    request_headers = get_request_headers_as_dict(request)
    response_headers = get_response_headers_as_dict(response)
    info_request = helpers.analyzeRequest(request)
    info_response = helpers.analyzeResponse(response)
    
    return (request, response, request_headers, response_headers, info_request, info_response)

def hyperlink(text, href):
    return "<a href={}>{}</a>".format(href, text)

def isOk(status):
    return status in (200, 201, 202, 204)


class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Unsafe JAX-RS")

        callbacks.registerScannerCheck(JaxRsScanner())
        callbacks.registerScannerCheck(JerseyScanner())
        callbacks.registerScannerCheck(CXFJaxRsScanner())
        callbacks.registerScannerCheck(ResteasyScanner())

        print "Successfully loaded Unsafe JAX-RS v" + VERSION

        return
    
    
class ScanIssue(IScanIssue):
    
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: " + name + " on " + str(url)
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService  


class JaxRsScanner(IScannerCheck):
    
    DESCR_WADL_SCAN = "JAX-RS application exposes {0}. You should check manually or using {1} that all resource methods " \
                      "have proper authentication/authorization.".format(
                          hyperlink("WADL","https://en.wikipedia.org/wiki/Web_Application_Description_Language"), 
                          hyperlink("SOAPUI","https://www.soapui.org/downloads/soapui.html"))
    
    DESCR_CONF_SCAN = "It seems that resource method of JAX-RS application lacks {0} annotation or have permissive media type specification " \
                      "e.g. \"application/*\". This can lead to situation when attacker can select \"bad\" {1} instead of intended provider. " \
                      "See {2}, {3}, {4} for more information about entity provider selection confusion vulnerabilities.".format(
                          hyperlink("@Consumes","https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"), 
                          hyperlink("Entity Provider","https://jersey.java.net/documentation/latest/message-body-workers.html"),
                          hyperlink("CVE-2016-7050","https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-7050"),
                          hyperlink("CVE-2016-9571","https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-9571"),
                          hyperlink("CVE-2016-8739","https://bugzilla.redhat.com/show_bug.cgi?id=1406811"))
                      
    DESCR_CSRF_SCAN = "It seems that resource method lacks {0} or allows text/plain media type. If class of entity parameter " \
                      "has valueOf(String) method or String constructor, this JAX-RS method might be vulnerable to CSRF attack.".format(
                          hyperlink("@Consumes","https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"))
                      
    DESCR_DOS_GZIP_SCAN = "JAX-RS resource method is vulnerable to DoS attack via decompression bomb. See {0}. " \
                          "Futher reading about decompression bombs - {1}.".format(
                              hyperlink("CVE-2016-6346","https://access.redhat.com/security/cve/cve-2016-6346"),
                              hyperlink("I Came to Drop Bombs ","https://www.blackhat.com/docs/us-16/materials/us-16-Marie-I-Came-to-Drop-Bombs-Auditing-The-Compression-Algorithm-Weapons-Cache.pdf"))
    
    DESCR_JSONP_SCAN = "JAX-RS resource method supports {0}. It might be vulnerable to {1} attack.".format(
                         hyperlink("JSONP","https://en.wikipedia.org/wiki/JSONP"),
                         hyperlink("XSSI","https://www.scip.ch/en/?labs.20160414"))
    
    DESCR_EXC_MAP_SCAN = "JAX-RS application uses exception mappers which exposes stacktrace and allows to identify JAX-RS library."
    
    DESCR_EXC_MAP_SCAN_XSS = "JAX-RS application uses exception mapper for JSON unmarshalling which is vulnerable to XSS attack. " \
                             "XSS vulnerability in RESTEasy - CVE-2016-6347".format(
                                 hyperlink("CVE-2016-6347","https://access.redhat.com/security/cve/cve-2016-6347"))
                             
    DESCR_URI_CT_NEG = "JAX-RS resource method supports negotiation of response media type via URI extension, e.g. /something.json." \
                       "It might lead to XSSI or XSS attacks."

    DESCR_XXE_SCAN = "It seems that resource method lacks {0} or specifies it too permisively. Additionally JAX-RS application has entity provider that is vulnerable to XXE. " \
                     "For example, JacksonJaxbXMLProvider which is the part of Jackson is known to be vulnerable to {1}.".format(
                        hyperlink("@Consumes", "https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"),
                        hyperlink("CVE-2016-3720", "https://bugzilla.redhat.com/show_bug.cgi?id=1328427"))

    
    def doPassiveScan(self, basePair):
        return []
      
    
    def doActiveScan(self, basePair, insertionPoint):
        issues = []
        
        self.request, self.response, self.request_headers, self.response_headers, self.info_request, self.info_response = prepare(basePair)
        self.httpService = basePair.getHttpService()
        self.URL = helpers.analyzeRequest(basePair).getUrl()

        if not should_trigger_per_request_attacks(self.info_request, insertionPoint):
            return []
        
        issues.extend(self.wadl_scan())
        issues.extend(self.confusion_scan())
        issues.extend(self.gzip_dos_scan())
        issues.extend(self.jsonp_scan())
        issues.extend(self.exception_mapper_scan())
        issues.extend(self.csrf_scan())
        issues.extend(self.uri_based_negotiation_scan())
        issues.extend(self.xxe_scan())
        
        return issues


    def xxe_scan(self):
        content_types = [
                            "application/xml",
                            "text/xml"
                        ]

        if not self.request_headers.has_key('Content-Length') or \
                        int(self.request_headers.get('Content-Length', 0)) == 0:
            return []

        for ct in content_types:
            request = safe_bytes_to_string(add_header_to_request(self.request, "Content-Type: ", ct))

            body = '<?xml version="1.0" encoding="utf-8"?>' + \
                   '<!DOCTYPE foo SYSTEM "%s://dummy" []>' + \
                   '<foo/>'
            r = get_random_string(10)
            body = body % r

            request = safe_bytes_to_string(add_body_to_request(request, body))

            newPair = callbacks.makeHttpRequest(self.httpService, request)
            response_modif = safe_bytes_to_string(newPair.getResponse())

            debug2console("XXE Scan", request, response_modif)

            if get_response_status_code(response_modif) in (400, 500) and r in response_modif:
                return [
                    ScanIssue(self.httpService, self.URL, [newPair],
                              "JAX-RS application has entity provider which is vulnerable to XXE",
                              CXFJaxRsScanner.DESCR_XXE_SCAN,
                              'Certain', 'High'),
                ]

        return []
    
    
    def csrf_scan(self):       
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        if self.info_request.getMethod() not in ('GET','POST'):
            return []
        
        if not self.request_headers.has_key('Content-Length') or \
                        int(self.request_headers.get('Content-Length',0)) == 0:
            return []
        
        request = safe_bytes_to_string( add_header_to_request(self.request, "Content-Type: ", "text/plain") )
        
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string( newPair.getResponse() )
        
        debug2console("CSRF scan valueOf", request, response_modif)
        
        if get_response_status_code(response_modif) != 415:
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        'JAX-RS resource method is vulnerable to CSRF',
                        JaxRsScanner.DESCR_CSRF_SCAN,
                        'Firm', 'Medium'),
                    ]
        return [] 
    
    
    def wadl_scan(self):
        """ Possible wadl servlet path values """
        names = [
                'application.xml',
                'application.wadl'
                ]
        
        path = self.info_request.getHeaders()[0].split(' ')[1]
        path_list = path.split('/')
        
        request = self.request
        
        if self.info_request.getMethod() != 'GET':
            request = safe_bytes_to_string( helpers.toggleRequestMethod(request) )
        
        for i in range(1,len(path_list)) :
            for name in names:
                _path = "/".join(path_list[:i]) + "/" + name
                _request = request.replace(path, _path, 1)
                
                modifPair = callbacks.makeHttpRequest(self.httpService, _request)
                response_modif = safe_bytes_to_string(modifPair.getResponse())
                
                debug2console("WADL Scan generic",_request,response_modif)
                
                _ct = get_response_headers_as_dict(response_modif).get('Content-Type')
         
                if isOk(get_response_status_code(response_modif)) and \
                    _ct in ("application/xml", "application/vnd.sun.wadl+xml"):
                    
                    return [
                        ScanIssue(self.httpService, self.URL, [ modifPair ],
                            "JAX-RS application exposes WADL",
                            JaxRsScanner.DESCR_WADL_SCAN,
                            'Certain', 'Medium'),
                    ] 
        return []

    
    def confusion_scan(self):
        """ Interesting Content-Types to check """     
        confusion_cts = (
                         "", # empty
                         "application/xml",
                         "text/xml",
                         "application/atom+xml",
                         "application/x-yaml",
                         "text/yaml", 
                         "application/x-kryo",
                         "application/x-stream",
                         "application/x-java-serialized-object",
                         "text/plain;charset=" + get_random_string(10)
                         )
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        if not self.request_headers.has_key('Content-Length') or \
                        int(self.request_headers.get('Content-Length',0)) == 0:
            return []
        
        issues = []
        for ct in confusion_cts:
            _request = safe_bytes_to_string( add_header_to_request(self.request, "Content-Type: ", ct) )

            body = get_random_string(10)
        
            _request = safe_bytes_to_string( add_body_to_request(_request, body) )
        
            newPair = callbacks.makeHttpRequest(self.httpService, _request)
            response_modif = safe_bytes_to_string(newPair.getResponse())
        
            debug2console("Confusion Scan", ct, _request, response_modif)
        
            if get_response_status_code(response_modif) in (500, 400):
                issues.append(ScanIssue(self.httpService, self.URL, [ newPair ],
                             "JAX-RS application is vulnerable to entity provider selection confusion",
                             JaxRsScanner.DESCR_CONF_SCAN,
                             "Firm", "High"))
        return issues       
    
    
    def gzip_dos_scan(self):
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        if not self.request_headers.has_key('Content-Length') or \
                        int(self.request_headers.get('Content-Length',0)) == 0:
            return []
        
        body = gzip_encode(get_request_body( self.request ))
        
        _request = safe_bytes_to_string(add_header_to_request(self.request, 'Content-Encoding: ', 'gzip'))
        _request = safe_bytes_to_string( add_body_to_request(_request, body) )
        
        modifPair = callbacks.makeHttpRequest(self.httpService, _request )
        response_modif = safe_bytes_to_string(modifPair.getResponse())
        
        debug2console("GZIP DoS Scan", response_modif)
        
        if isOk(get_response_status_code(response_modif)) and \
            self.response_headers.get('Content-Type') == get_response_headers_as_dict(response_modif).get('Content-Type'):
            
            return [
                    ScanIssue(self.httpService, self.URL, [ modifPair, ],
                    "JAX-RS resource is vulnerable to GZIP bombing DoS",
                    JaxRsScanner.DESCR_DOS_GZIP_SCAN,
                    "Certain", "Medium"),
                    ]
        return []
    
    
    def jsonp_scan(self):
        """ Possible parameter names for JSONP """
        jsnop_param_names = [
                         "callback",
                         "_callback",
                         "__callback",
                         "jsonp",
                         "_jsonp",
                         "__jsonp",
                         "func",
                         "function"
                         ]
        
        if not isOk(self.info_response.getStatusCode()):
            return []
                       
        value = get_random_string(10)
        
        for param_name in jsnop_param_names:
            param = helpers.buildParameter(param_name , value, IParameter.PARAM_URL)
            _request = safe_bytes_to_string( helpers.addParameter(self.request,param) )
        
            newPair = callbacks.makeHttpRequest(self.httpService, _request)
            response_modif = safe_bytes_to_string( newPair.getResponse() )
        
            debug2console("JSONP Scan", _request, response_modif)
        
            if value + "(" in response_modif:
                return [
                        ScanIssue(self.httpService, self.URL, [ newPair ],
                        "JAX-RS resource method supports JSONP",
                        JaxRsScanner.DESCR_JSONP_SCAN,
                        'Firm', 'Medium'),
                        ]
        return []
    
    
    def exception_mapper_scan(self):
        issues = []
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        path = self.info_request.getHeaders()[0].split(' ')[1]
        path_list = path.split('/')
        
        for i in range(1,len(path_list)):  ### Check for PathParam processing exceptions
            _path_list = path_list[:]
            _path_list[i] = choice("{}[]\\")
            
            _path = "/".join(_path_list)
            _request = self.request.replace(path, _path, 1)
            
            modifPair = callbacks.makeHttpRequest(self.httpService, _request )
            response_modif = safe_bytes_to_string(modifPair.getResponse())
            
            debug2console("PathParam processing exception", _request, response_modif)
            
            if get_response_status_code(response_modif) == 500:
                issues.append(
                    ScanIssue(self.httpService, self.URL, [ modifPair ],
                    "Exception occured during Path Param processing",
                    JaxRsScanner.DESCR_EXC_MAP_SCAN,
                    'Certain', 'Low')
                )
                break
        
        ACCEPT = get_random_string(10) + "/" + get_random_string(10)  ### Check for exceptions during marshalling
        _request = add_header_to_request(self.request, "Accept: ", ACCEPT)
        
        modifPair = callbacks.makeHttpRequest(self.httpService, _request )
        response_modif = safe_bytes_to_string(modifPair.getResponse())
        
        debug2console("Marshalling exceptions", _request, response_modif)
        
        if get_response_status_code(response_modif) == 500:
            issues.append(
                ScanIssue(self.httpService, self.URL, [ modifPair ],
                "Exception occured during marshalling",
                JaxRsScanner.DESCR_EXC_MAP_SCAN,
                'Certain', 'Low')
            )
        
        if not self.request_headers.has_key('Content-Length') or \
                        int(self.request_headers.get('Content-Length',0)) == 0:
            return issues
        
        if 'application/json' in self.request_headers['Content-Type']: ### Check for exceptions during JSON unmarshalling
            value = get_random_string(10)
            body = '{"<%s>":1}' % value
            _request = safe_bytes_to_string(add_body_to_request(self.request, body))
            
            modifPair = callbacks.makeHttpRequest(self.httpService, _request )
            response_modif = safe_bytes_to_string(modifPair.getResponse())
            
            debug2console("Unmarshalling exceptions", _request, response_modif)
            
            if "<%s>" % value in response_modif:
                if "text/html" in get_response_headers_as_dict(response_modif).get('Content-Type',''):
                    issues.append(
                        ScanIssue(self.httpService, self.URL, [ modifPair ],
                        "JAX-RS exception mapper is vulnerable to XSS",
                        JaxRsScanner.DESCR_EXC_MAP_SCAN_XSS,
                        'Certain', 'Medium')
                    )
                else:
                    issues.append(
                        ScanIssue(self.httpService, self.URL, [ modifPair ],
                        "Exception occured during JSON unmarshalling",
                        JaxRsScanner.DESCR_EXC_MAP_SCAN,
                        'Certain', 'Low')
                    )
        return issues
    
    
    def uri_based_negotiation_scan(self):
        """ Content-Types to extension mapping """
        mappings = {
                    "application/json" :        ".json",
                    "application/xml" :         ".xml",
                    "text/xml":                 ".xml",
                    "application/atom+xml":     ".atom",
                    "text/plain":               ".txt",
                    "text/html":                ".html",
                    "application/x-javascript": ".js"
                    }
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        ct = self.response_headers.get('Content-Type','')
        ext = mappings.get(ct, ".json")
            
        ACCEPT = get_random_string(10) + "/" + get_random_string(10)
        request = add_header_to_request(self.request, "Accept: ", ACCEPT)
        
        path = urlparse(str(self.URL)).path
        
        request = request.replace(path, path + ext, 1)
        
        modifPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string( modifPair.getResponse() )
        
        debug2console("URI-based negotiation scan", request, response_modif)
        
        if isOk(get_response_status_code(response_modif)) and \
            self.response_headers.get('Content-Type') == get_response_headers_as_dict(response_modif).get('Content-Type'):
        
            return [
                ScanIssue(self.httpService, self.URL, [ modifPair ],
                "JAX-RS resource method supports URI-based content negotiation",
                JaxRsScanner.DESCR_URI_CT_NEG,
                "Firm", "Medium"),
                ]
        return []
        
        
class JerseyScanner(IScannerCheck):
    
    DESCR_WADL_SCAN = "Jersey application exposes {0}. You should check manually or using {1} that all resource methods " \
                      "have proper authentication/authorization.".format(
                          hyperlink("WADL","https://en.wikipedia.org/wiki/Web_Application_Description_Language"), 
                          hyperlink("SOAPUI","https://www.soapui.org/downloads/soapui.html"))
    
    def doPassiveScan(self, basePair):
        return []
    
    
    def doActiveScan(self, basePair, insertionPoint):
        issues = []
        
        self.request, self.response, self.request_headers, self.response_headers, self.info_request, self.info_response = prepare(basePair)
        self.httpService = basePair.getHttpService()
        self.URL = helpers.analyzeRequest(basePair).getUrl()

        if not should_trigger_per_request_attacks(self.info_request, insertionPoint):
            return []
            
        issues.extend(self.wadl_scan())

        return issues
    
    
    def wadl_scan(self):
        request = self.request

        if self.info_request.getMethod() != 'GET':
            request = safe_bytes_to_string(helpers.toggleRequestMethod(request))
            
        request = safe_bytes_to_string(add_header_to_request(request, "Accept: ", "application/vnd.sun.wadl+xml"))
        
        request_options = request.replace("GET ", "OPTIONS ", 1)
        
        newPair = callbacks.makeHttpRequest(self.httpService, request_options)
        resp = safe_bytes_to_string(newPair.getResponse())
        
        debug2console("WADL Scan Jersey", request, resp)
        
        if not (isOk(get_response_status_code(resp)) and \
                    get_response_headers_as_dict(resp).get('Content-Type') == 'application/vnd.sun.wadl+xml'):
            return []
        
        m = search('(?im)<resources\s+base\s*=\s*"([^"]*)"',resp)
        if not m:
            return []
        
        new_path = urlparse(m.group(1)).path
        
        request = add_header_to_request(request, "GET ", "%sapplication.wadl?detail=true HTTP/1.1" % new_path)
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        resp = safe_bytes_to_string(newPair.getResponse())
        
        debug2console("WADL Scan Jersey", request, resp)
        
        return [
                ScanIssue(self.httpService, self.URL, [ newPair ],
                    "Jersey application exposes WADL",
                    JerseyScanner.DESCR_WADL_SCAN,
                    'Certain', 'Medium'),
                ]


class CXFJaxRsScanner(IScannerCheck):
    
    DESCR_CXF_SCAN = "Apache CXF RS application is detected. CXF supposts _method URL parameter, see - {0}.".format(
                        hyperlink("JAX-RS Debugging","http://cxf.apache.org/docs/jax-rs.html#JAX-RS-Debugging"))
    
    DESCR_GZIP_DOS_SCAN = "Apache CXF RS application is vulnerbale to DoS via GZIP decompression bombing. See - {0}.".format(
                                hyperlink("CVE-2016-6346","https://access.redhat.com/security/cve/cve-2016-6346"))
    
    DESCR_WADL_SCAN = "Apache CXF RS application exposes {0}. You should check manually or using {1} that all resource methods " \
                      "have proper authentication/authorization.".format(
                          hyperlink("WADL","https://en.wikipedia.org/wiki/Web_Application_Description_Language"), 
                          hyperlink("SOAPUI","https://www.soapui.org/downloads/soapui.html"))
                      
    DESCR_CVE_2016_8739_SCAN = "Resource method of Apache CXF RS application lacks {0} annotation or have permissive media type specification. " \
                               "Apache CXF is vulnerable to XXE attack - {1}. Attacker can trigger unmarshalling using vulnerable Atom provider " \
                               "by specifying application/atom+xml Content-Type header.".format(
                                   hyperlink("@Consumes","https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"), 
                                   hyperlink("CVE-2016-8739","https://bugzilla.redhat.com/show_bug.cgi?id=1406811"))
                               
    DESCR_CSRF_SCAN = "Apache CXF RS resource method migth be vulnerable to CSRF attack. URL parameters {0} and {1} are supported." \
                      "Parameter _method allows to override HTTP request method. Parameter _ctype allows to override Content-Type header".format(
                          hyperlink("_method","http://cxf.apache.org/docs/jax-rs.html#JAX-RS-Debugging"),
                          hyperlink("_ctype","http://cxf.apache.org/docs/jax-rs.html#JAX-RS-Debugging")
                          )
    
     
    def doActiveScan(self, basePair, insertionPoint):
        issues = []
        
        self.request, self.response, self.request_headers, self.response_headers, self.info_request, self.info_response = prepare(basePair)
        self.httpService = basePair.getHttpService()
        self.URL = helpers.analyzeRequest(basePair).getUrl()

        if not should_trigger_per_request_attacks(self.info_request, insertionPoint):
            return []
        
        issues.extend(self.cxf_scan())
        issues.extend(self.wadl_scan())
        issues.extend(self.csrf_scan())
        issues.extend(self.detect_gzip_dos())
        issues.extend(self.cve_2016_8739_scan())
        
        return issues
 
 
    def doPassiveScan(self, basePair):
        return []
     
     
    def cxf_scan(self):
        _methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        param = helpers.buildParameter("_method", self.info_request.getMethod(), IParameter.PARAM_URL)
        _methods.remove(self.info_request.getMethod())
        request = safe_bytes_to_string( helpers.addParameter(self.request, param) )
         
        request = request.replace(self.info_request.getMethod(), choice(_methods), 1)
         
        modifPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string(modifPair.getResponse())
        
        debug2console("Detect CXF Scan", request, response_modif)

        if isOk(get_response_status_code(response_modif)) and \
          self.response_headers.get('Content-Type') == get_response_headers_as_dict(response_modif).get('Content-Type'):
            return [
                    ScanIssue(self.httpService, self.URL,[ modifPair ],
                        "Apache CXF RS application",
                        CXFJaxRsScanner.DESCR_CXF_SCAN,
                        'Certain', 'Information'),
                    ] 
        return []
     
     
    def detect_gzip_dos(self):
        _message = "java.util.zip.ZipException"
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        request = self.request
        
        if self.info_request.getMethod() == 'GET':
            request = helpers.toggleRequestMethod(request)
             
            param = helpers.buildParameter("_method", "GET", IParameter.PARAM_URL)
            request = safe_bytes_to_string(helpers.addParameter(request,param))
             
            request = safe_bytes_to_string( add_body_to_request(request, get_random_string(10)) )
         
        request = add_header_to_request(request, 'SOAPJMS_contentEncoding: ', 'x-gzip')
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        resp = safe_bytes_to_string(newPair.getResponse())
         
        debug2console("CXF GZIP DoS Scan", request, resp)
         
        if _message in get_response_body(resp):
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                             "Apache CXF RS application GZIP DoS attack",
                             CXFJaxRsScanner.DESCR_GZIP_DOS_SCAN,
                             'Certain', 'Medium')
                    ]
        return []
     
     
    def wadl_scan(self):
        request = self.request
         
        if self.info_request.getMethod() != 'GET':
            request = helpers.toggleRequestMethod(request)
             
        param = helpers.buildParameter("_wadl", "true", IParameter.PARAM_URL)
        request = safe_bytes_to_string(helpers.addParameter(request, param))
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        resp = safe_bytes_to_string(newPair.getResponse())
         
        debug2console("CXF WADL Scan", request, resp)
         
        if not (isOk(get_response_status_code(resp)) and \
                    get_response_headers_as_dict(resp).get('Content-Type') == 'application/xml'):
            return []
         
        m = search('(?im)<resources\s+base\s*=\s*"([^"]*)"',resp)
        if not m:
            return []
         
        new_path = urlparse(m.group(1)).path
         
        request = add_header_to_request(request, "GET ", "%s?_wadl=true HTTP/1.1" % new_path)
        newPair = callbacks.makeHttpRequest(self.httpService, request )
        resp = safe_bytes_to_string(newPair.getResponse())
         
        debug2console("CXF WADL Scan", request, resp)
         
        return [
                ScanIssue(self.httpService, self.URL, [ newPair ],
                    "Apache CXF RS application exposes WADL",
                    CXFJaxRsScanner.DESCR_WADL_SCAN,
                    'Certain', 'Medium'),
                ]
 
     
    def csrf_scan(self):
        """ Content-Type to _ctype values mapping """
        ctype_dict = {
                      "application/json" : "json",
                      "application/xml" : "xml",
                      "application/atom+xml" : "atom"
                      }
        
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        if self.info_request.getMethod() == 'GET' and \
            (not self.request_headers.has_key('Content-Length') or \
                    int(self.request_headers.get('Content-Length',0)) == 0):
            return []
                
        body = get_request_body(safe_bytes_to_string(self.request))
        request = helpers.toggleRequestMethod(self.request)
        
        if self.info_request.getMethod() != 'GET':
            param = helpers.buildParameter("_method", self.info_request.getMethod(), IParameter.PARAM_URL)
            request = safe_bytes_to_string(helpers.addParameter(request, param))
        
        ctype = ctype_dict.get(self.request_headers['Content-Type'], "json")
        param = helpers.buildParameter("_ctype", ctype, IParameter.PARAM_URL)
        request = safe_bytes_to_string(helpers.addParameter(request, param))
                    
        request = safe_bytes_to_string( add_body_to_request(request, body) )
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string(newPair.getResponse())
         
        debug2console("CXF CSRF Scan", request, response_modif)
         
        if isOk(get_response_status_code(response_modif)) and \
          self.response_headers.get('Content-Type') == get_response_headers_as_dict(response_modif).get('Content-Type'):
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "Apache CXF RS resource method is vulnerable to CSRF",
                        CXFJaxRsScanner.DESCR_CSRF_SCAN,
                        'Firm', 'Medium'),
                    ]
        return []
     
     
    def cve_2016_8739_scan(self):
        if not self.request_headers.has_key('Content-Length') or \
                    int(self.request_headers.get('Content-Length',0)) == 0:
            return []
         
        request = safe_bytes_to_string( add_header_to_request(self.request, "Content-Type: ", "application/atom+xml") )
 
        body = '<?xml version="1.0" encoding="utf-8"?>' + \
            '<!DOCTYPE feed SYSTEM "nosuch://%s" []>' + \
            '<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        r = get_random_string(10)
        body = body % r
         
        request = safe_bytes_to_string( add_body_to_request(request, body) )
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string(newPair.getResponse())
         
        debug2console("CVE-2016-8739 Scan", request, response_modif)
         
        if get_response_status_code(response_modif) in (400, 500) and r in response_modif:
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "Apache CXF RS resource method is vulnerable to CVE-2016-8739",
                        CXFJaxRsScanner.DESCR_CVE_2016_8739_SCAN,
                        'Certain', 'High'),
                    ]
        return []
    
    
class ResteasyScanner(IScannerCheck):
    
    DESCR_CVE_2016_7050_SCAN = "Resource method of RESTEasy application lacks {0} annotation or have permissive media type specification. " \
                               "RESTEasy is vulnerable to Java deserialization attack - {1}. Attacker can trigger unmarshalling using vulnerable Serializable provider " \
                               "by specifying application/x-java-serialized-object Content-Type header.".format(
                                   hyperlink("@Consumes","https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"), 
                                   hyperlink("CVE-2016-7050","https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-7050"))
                               
    DESCR_ASYNCH_SCAN = "RESTEasy application supports {0}. It might be vulnerable to {1}.".format(
                            hyperlink("Async jobs","http://docs.jboss.org/resteasy/docs/3.1.0.Final/userguide/html_single/index.html#async_job_service"), 
                            hyperlink("CVE-2016-6345","https://access.redhat.com/security/cve/cve-2016-6345"))
    
    DESCR_CVE_2016_9571_SCAN = "Resource method of RESTEasy application lacks {0} annotation or have permissive media type specification. " \
                               "RESTEasy is vulnerable to Yaml unmarshalling attack - {1}. Attacker can trigger unmarshalling using vulnerable Yaml provider " \
                               "by specifying text/yaml Content-Type header.".format(
                                   hyperlink("@Consumes","https://docs.oracle.com/cd/E19776-01/820-4867/ggqqr/"), 
                                   hyperlink("CVE-2016-9571","https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-9571"))
    
    DECSR_URL_PARAM_CT_MAPPING_SCAN = "RESTEasy application supports response content type negotiation via {0}. " \
                                      "It might be vulnerable to XSSI or XSS attacks.".format(
                                          hyperlink("query string parameter","http://docs.jboss.org/resteasy/docs/3.1.0.Final/userguide/html_single/index.html#param_media_mappings"))
    
    
    def doActiveScan(self, basePair, insertionPoint):
        issues = []
        
        self.request, self.response, self.request_headers, self.response_headers, self.info_request, self.info_response = prepare(basePair)
        self.httpService = basePair.getHttpService()
        self.URL = helpers.analyzeRequest(basePair).getUrl()

        if not should_trigger_per_request_attacks(self.info_request, insertionPoint):
            return []
        
        issues.extend(self.cve_2016_7050_scan())
        issues.extend(self.cve_2016_9571_scan())
        issues.extend(self.asynch_scan())
        issues.extend(self.url_mapping_scan())
        
        return issues
 
    
    def doPassiveScan(self, basePair):
        return []
    

    def cve_2016_7050_scan(self):
        if not self.request_headers.has_key('Content-Length') or \
                    int(self.request_headers.get('Content-Length',0)) == 0:
            return []
         
        request = safe_bytes_to_string( add_header_to_request(self.request, "Content-Type: ", "application/x-java-serialized-object") )
 
        body = get_random_string(4)
         
        request = safe_bytes_to_string( add_body_to_request(request, body) )
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string( newPair.getResponse() )
         
        debug2console("CVE-2016-7050 Scan", request, response_modif)
         
        if get_response_status_code(response_modif) in (400, 500) and "java.io.StreamCorruptedException" in response_modif:
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "RESTEasy resource method is vulnerable to CVE-2016-7050",
                        ResteasyScanner.DESCR_CVE_2016_7050_SCAN,
                        'Certain', 'High'),
                    ]
        return []
    
    
    def cve_2016_9571_scan(self):
        if not self.request_headers.has_key('Content-Length') or \
                    int(self.request_headers.get('Content-Length',0)) == 0:
            return []
         
        request = safe_bytes_to_string( add_header_to_request(self.request, "Content-Type: ", "text/yaml") )
 
        body = get_random_string(10)
         
        request = safe_bytes_to_string( add_body_to_request(request, body) )
         
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string( newPair.getResponse() )
         
        debug2console("CVE-2016-9571 Scan", request, response_modif)
         
        if get_response_status_code(response_modif) in (400, 500) and "java.lang.String " + body in response_modif:
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "RESTEasy resource method is vulnerable to CVE-2016-9571",
                        ResteasyScanner.DESCR_CVE_2016_9571_SCAN,
                        'Certain', 'High'),
                    ]
        return []
    
    
    def asynch_scan(self):
        if not isOk(self.info_response.getStatusCode()):
            return []
        
        param = helpers.buildParameter("asynch", "true", IParameter.PARAM_URL)
        request = safe_bytes_to_string( helpers.addParameter(self.request, param) )
        
        newPair = callbacks.makeHttpRequest(self.httpService, request)
        response_modif = safe_bytes_to_string( newPair.getResponse() )
        
        debug2console("Asynch Scan", request, response_modif)
        
        if get_response_status_code(response_modif) == 202 and \
            "asynch" in get_response_headers_as_dict(response_modif).get('Location',''):
            
            return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "RESTEasy application supports async jobs",
                        ResteasyScanner.DESCR_ASYNCH_SCAN,
                        'Firm', 'Medium'),
                    ]
        return []
    
    
    def url_mapping_scan(self):
        """ Possible names of URL parameter for media type mapping  """
        param_names = [
                        "accept",
                        "_accept",
                        "__accept",
                        "format",
                        "_format",
                        "__format",
                        "ctype",
                        "_ctype",
                        "__ctype"
                       ]
        
        if not isOk(self.info_response.getStatusCode()):
            return []
               
        for name in param_names:
            param = helpers.buildParameter(name, get_random_string(10), IParameter.PARAM_URL)
            _request = safe_bytes_to_string( helpers.addParameter(self.request, param) )
            
            newPair = callbacks.makeHttpRequest(self.httpService, _request)
            response_modif = safe_bytes_to_string(newPair.getResponse())
        
            debug2console("URL Mapping Scan", _request, response_modif)
            
            if get_response_status_code(response_modif) == 500:
                return [
                    ScanIssue(self.httpService, self.URL, [ newPair ],
                        "RESTEasy application supports content negotiation via URL parameter",
                        ResteasyScanner.DECSR_URL_PARAM_CT_MAPPING_SCAN,
                        'Firm', 'Medium'),
                    ]
        return []