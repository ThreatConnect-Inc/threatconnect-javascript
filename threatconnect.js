/*
 Copyright 2015 ThreatConnect, Inc.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 =============================================================================
*/

/* global CryptoJS, TYPE */

var c = console,
    ct = console.table;

// const TYPE = {  // ECMASCRIPT6 support only
var TYPE = {
    ADDRESS: {
        'dataField': 'address',
        'postField': 'ip',
        'indicatorFields': ['ip'],
        'type': 'Address',
        'uri': 'indicators/addresses',
    },
    ADVERSARY: {
        'dataField': 'adversary',
        'type': 'Adversary',
        'uri': 'groups/adversaries',
    },
    DOCUMENT: {
        'dataField': 'document',
        'type': 'Document',
        'uri': 'groups/documents',
    },
    EMAIL: {
        'dataField': 'email',
        'type': 'Email',
        'uri': 'groups/emails',
    },
    EMAIL_ADDRESS: {
        'dataField': 'emailAddress',
        'postField': 'address',
        'indicatorFields': ['address'],
        'type': 'EmailAddress',
        'uri': 'indicators/emailAddresses',
    },
    FILE: {
        'dataField': 'file',
        'postField': '',
        'indicatorFields': ['md5', 'sha1', 'sha256'],
        'type': 'File',
        'uri': 'indicators/files',
    },
    GROUP: {
        'dataField': 'group',
        'type': 'Group',
        'uri': 'groups',
    },
    HOST: {
        'dataField': 'host',
        'postField': 'hostName',
        'indicatorFields': ['hostName'],
        'type': 'Host',
        'uri': 'indicators/hosts',
    },
    INCIDENT: {
        'dataField': 'incident',
        'type': 'Incident',
        'uri': 'groups/incidents',
    },
    INDICATOR: {
        'dataField': 'indicator',
        'type': 'Indicator',
        'uri': 'indicators',
    },
    SIGNATURE: {
        'dataField': 'signature',
        'type': 'Signature',
        'uri': 'groups/signatures',
    },
    THREAT: {
        'dataField': 'threat',
        'type': 'Threat',
        'uri': 'groups/threats',
    },
    URL: {
        'dataField': 'url',
        'postField': 'text',
        'indicatorFields': ['text'],
        'type': 'URL',
        'uri': 'indicators/urls',
    }
};

function indicatorHelper(prefix) {
    var iTypes = {
        'a': TYPE.ADDRESS,
        'e': TYPE.EMAIL_ADDRESS,
        'f': TYPE.FILE,
        'h': TYPE.HOST,
        'u': TYPE.URL
    };
    return iTypes[prefix];
}
    
function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(location.search);
        
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}
    
function getParameterFromUri(name, uri) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(uri);
        
    return results === null ? undefined : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function RequestObject(params) {
    c.groupCollapsed('RequestObject');

    // this.id = uuid.v4();
    this._async = true,
    this._contentType = 'application/json; charset=UTF-8',
    this._done = undefined,
    this._error = undefined,
    this._headers = {},
    this._helper = false,
    this._limit = 1000000,
    this._normalizer = normalize.default,
    this._owner = undefined,
    this._pagination = undefined,
    this._pathUrl = undefined,
    this._payload = {
        resultLimit: 500,
    },
    this._remaining = 0,
    this._requestUri = undefined,
    this._resultLimit = 500,
    this._resultStart = 0,
    this._type = undefined,
    this.response = {
        apiCalls: 0,
        body: undefined,
        data: [],
        error: undefined,
        id: undefined,
        requestMethod: 'GET',
        resultCount: 0,
        status: undefined,
    };

    this.payload = function(key, val) {
        // TODO: validate supported parameters
        this._payload[key] = val;
        return this;
    };
    
    this.addHeader = function(key, val) {
        this._headers[key] = val;
        return this;
    };
    
    this.activityLog = function(data) {
        if (boolCheck('activityLog', data)) {
            this.payload('createActivityLog', data.toString());
        }
        return this;
    };
    
    this.async = function(data) {
        if (boolCheck('async', data)) {
            this._async = data;
        }
        return this;
    };
    
    this.body = function(data) {
        this.response.body = JSON.stringify(data);
        if (data.id) {
            this.response.id = data.id;
        }
        return this;
    };
    
    this.contentType = function(data) {
        this._contentType = data;
        return this;
    };
    
    this.done = function(data) {
        if (data) {
            if (functionCheck('done', data)) { this._done = data; }
        }
        return this;
    };
    
    this.error = function(data) {
        if (data) {
            if (functionCheck('error', data)) { this._error = data; }
        }
        return this;
    };
    
    this.helper = function(data) {
        this._helper = data;
        return this;
    };
    
    this.id = function(data) {
        this.response.id = data;
        return this;
    };
    
    this.limit = function(data) {
        if (data) {
            if (intCheck('limit', data)) {
                this._limit = data;
                if (data < 500) {
                    this._resultLimit = data;
                    this.payload('resultLimit', data);
                }
            }
        }
        return this;
    };
    
    this.modifiedSince = function(data) {
        this.payload('modifiedSince', data);
        return this;
    };
    
    this.normalization = function(method) {
        this._normalizer = method;
        return this;
    };
    
    this.owner = function(data) {
        this.payload('owner', data);
        this._owner = data;
        return this;
    };
    
    this.pagination = function(data) {
        if (data) {
            if (functionCheck('pagination', data)) { this._pagination = data; }
        }
        return this;
    };
    
    this.remaining = function(data) {
        this._remaining = data;
        return this;
    };
    
    this.requestUri = function(uri) {
        this._requestUri = uri;
        return this;
    };
    
    this.requestMethod = function(method) {
        this.response.requestMethod = method;
        return this;
    };
    
    this.resultCount = function(data) {
        this.response.resultCount = data;
        return this;
    };
    
    this.resultLimit = function(data) {
        if (rangeCheck('resultLimit', data, 1, 500)) {
            if (this._limit > 500) {
                this.payload('resultLimit', data);
                this._resultLimit = data;
            }
        }
        return this;
    };
    
    this.resultStart = function(data) {
        this.payload('resultStart', data);
        this._resultStart = data;
        return this;
    };
    
    this.type = function(data) {
        this._type = data;
        return this;
    };
    
    c.groupEnd();
    return this;
}

function ThreatConnect(params) {
    if (!!(params.apiId && params.apiKey && params.apiUrl) && !!(params.apiToken && params.apiUrl)) { return false; }
    
    this.apiId = params.apiId;
    this.apiSec = params.apiSec;
    this.apiToken = params.apiToken;
    this.apiUrl = (params.apiUrl ? params.apiUrl : 'https://api.threatconnect.com');
    // secondary restriction if browser does not limit concurrent api requests
    this.concurrentCalls = (params.concurrentCalls ? params.concurrentCalls : 10);
    
    this.apiHmacRequestHeader = function (ro) {
        // c.log('using HMAC');
        this._getTimestamp = function() {
            var date = new Date().getTime();
            return Math.floor(date / 1000);
        };
        
        var timestamp = this._getTimestamp(),
            signature = [ro._pathUrl, ro.response.requestMethod, timestamp].join(':'),
            hmacSignature = CryptoJS.HmacSHA256(signature, this.apiSec),
            authorization = 'TC ' + this.apiId + ':' + CryptoJS.enc.Base64.stringify(hmacSignature);
    
        ro.addHeader('Timestamp', timestamp),
        ro.addHeader('Authorization', authorization);
    };
    
    this.apiTokenRequestHeader = function (ro) {
        // c.log('using Token');
        ro.addHeader('authorization', "TC-Token " + this.apiToken);
    };
    
    this.apiRequestUrl = function(host, pathname, search) {
        var url = document.createElement('a');
        url.href =  host + '/' + pathname;
        if (Object.keys(search).length) {
            url.href = url.href + '?' + $.param(search);
        }
        return url;
    };
    
    this.apiRequest = function(ro) {
        c.group('apiRequest');
        c.log('ro', ro);
        
        var _this = this,
            url = this.apiRequestUrl(this.apiUrl, ro._requestUri, ro._payload);
            
        if (this.apiToken) {
            this.apiTokenRequestHeader(ro);
        } else {
            // set pathname for hmac encryption
            ro._pathUrl = url.pathname + url.search;
            this.apiHmacRequestHeader(ro);
        }
            
        // jQuery ajax does not allow query string paramaters and body to
        // be used at the same time.  The url has to rebuilt manually.
        // first api call will always be synchronous to get resultCount
        var defaults = {
            aysnc: false,
            url: ro.response.requestMethod === 'GET' ? [this.apiUrl, ro._requestUri].join('/') : url.href,
            data: ro.response.requestMethod === 'GET' ? ro._payload : ro.response.body,
            headers: ro._headers,
            crossDomain: false,
            method: ro.response.requestMethod,
            contentType: ro._contentType,
        };
        // c.log('url.href', url.href);
        // c.log('defaults', defaults);
        
        c.groupEnd();
        // make first api call
        return $.ajax(defaults)
            // .always(function (response) {
            .done(function (response) {
                c.log('response', response);
                var upload_pattern = /upload/;
                
                // increment api call count
                ro.response.apiCalls++;
                
                if (ro._helper === false) {
                    // if (ro._done) { ro._done(ro.response); }
                    if (ro._done) { ro._done(response); }
                    return;
                }
                
                // set status code
                ro.response.status = response.status;
                
                if (response.status == 'Success' && ro._pagination) {
                    // callback for paginated results
                    ro._pagination(ro._normalizer(ro, response));
                } else {
                    ro._normalizer(ro, response);
                }
                
                // check for pagination support
                if (response.data) {
                    if (response.data.resultCount) {
                        ro.resultCount(response.data.resultCount)
                            .resultStart(ro._resultStart + ro._resultLimit)
                            .remaining(ro.response.resultCount - ro._resultLimit);
                            
                        // c.log('ro.resonse.resultCount', ro.resonse.resultCount);
                        // c.log('ro._remaining', ro._remaining);
                        
                        _this.apiRequestPagination(ro);
                    } else {
                        // callback for done
                        if (ro._done) { ro._done(ro.response); }
                    }
                } else if (upload_pattern.test(ro._requestUri)) {
                    if (ro._done) { ro._done(ro.response); }
                } else if (ro.response.requestMethod === 'DELETE') {
                    if (ro._done) { ro._done(ro.response); }
                }
            })
            .fail(function (response) {
                c.log('fail response', response);
                ro.response.error = response.responseText;
                
                ro._error(ro.response);
            });
    };
    
    this.apiRequestPagination = function(ro) {
        var _this = this;
        c.group('apiRequestPagination');
                
        var ajaxRequests = [];
        for (var i=1;i<=this.concurrentCalls;i++) {
            c.log('ro._remaining', ro._remaining);
            
            if (ro.response.data.length >= ro._limit || ro._remaining <= 0) {
                break;
            }
            
            var url = this.apiRequestUrl(this.apiUrl, ro._requestUri, ro._payload);
            
            if (this.apiToken) {
                this.apiTokenRequestHeader(ro);
            } else {
                // set pathname for hmac encryption
                ro._pathUrl = url.pathname + url.search;
                this.apiHmacRequestHeader(ro);
            }
         
            // jQuery ajax does not allow query string paramaters and body to
            // be used at the same time.  The url has to rebuilt manually.
            // first api call will always be synchronous to get resultCount
            var defaults = {
                aysnc: ro.async,
                url: ro.response.requestMethod === 'GET' ? [this.apiUrl, ro._requestUri].join('/') : url.href,
                data: ro.response.requestMethod === 'GET' ? ro._payload : ro.response.body,
                headers: ro._headers,
                crossDomain: false,
                method: ro.response.requestMethod,
                contentType: ro._contentType,
            };
                
            ajaxRequests.push($.ajax(defaults).done(function(response) {
                // increment api call count
                ro.response.apiCalls++;
                
                if (typeof ro._pagination === 'function') {
                    // callback for paginated results
                    ro._pagination(ro._normalizer(ro, response));
                } else {
                    ro._normalizer(ro, response);
                }
            }));
            ro.resultStart(ro._resultStart + ro._resultLimit)
                .remaining(ro._remaining - ro._resultLimit);
        }
        // c.log('ajaxRequests', ajaxRequests);

        $.when.apply(jQuery, ajaxRequests).done(function () {
            // for (var i=0;i<arguments.length;i++) {
            //     console.log('Response for request #' + (i + 1) + ' is ' + arguments[i][0]);
            //     console.log(arguments[i][0]);
            // }
            if (ro._remaining > 0 && ro._limit > ro.response.data.length) {
                _this.apiRequestPagination(ro);
            } else {
                if (ro._done) { ro._done(ro.response); }
            }
        });
        c.groupEnd();
    };
    
    // this.adversaries = function() {
    //     return new Adversaries(this);
    // };
    
    // this.documents = function() {
    //     return new Documents(this);
    // };
    
    // this.emails = function() {
    //     return new Emails(this);
    // };
    
    this.attributes = function() {
        return new Attributes(this);
    };
    
    this.groups = function() {
        return new Groups(this);
    };
    
    // this.incidents = function() {
    //     return new Incidents(this);
    // };
    
    this.indicators = function() {
        return new Indicators(this);
    };
    
    this.owners = function() {
        return new Owners(this);
    };
    
    this.tags = function() {
        return new Tags(this);
    };
}

function Groups(threatconnect) {
    c.group('Group');
    ThreatConnect.call(this, threatconnect);
    
    this.settings = {
        api: {
            activityLog: false,             // false|true
            async: true,
            limit: undefined,
            normalizer: normalize.groups,
            requestUri: 'v2',
            requestUriType: 'groups',
            requestUriId: '',
            resultLimit: 500,
            type: TYPE.GROUP
        },
        callbacks: {
            done: undefined,
            error: undefined,
            pagination: undefined,
        },
    },
    this.rData = {
        optionalData: {},
        requiredData: {},
        specificData: {
            adversary: {},
            document: {},
            email: {},
            incident: {},
            signature: {},
            threat: {}
        },
    };
 
    //
    // Settings API
    //
    this.activityLog = function(data) {
        if (boolCheck('activityLog', data)) {
            this.settings.api.activityLog = data;
        }
        return this;
    };
    
    this.async = function(data) {
        if (boolCheck('async', data)) {
            this.settings.api.async = data;
        }
        return this;
    };
    
    this.limit = function(data) {
        if (intCheck('limit', data)) {
            this.settings.api.limit = data;
        }
        return this;
    };
    
    this.id = function(data) {
        this.settings.api.requestUriId = data;
        return this;
    };
    
    this.resultLimit = function(data) {
        if (rangeCheck('resultLimit', data, 1, 500)) {
            this.settings.api.resultLimit = data;
        }
        return this;
    };
 
    this.owner = function(data) {
        this.settings.api.owner = data;
        return this;
    };
 
    this.type = function(data) {
        this.settings.api.requestUriType = data.uri;
        this.settings.api.type = data;
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (functionCheck('done', data)) {
            this.settings.callbacks.done = data;
        }
        return this;
    };
    
    this.error = function(data) {
        if (functionCheck('error', data)) {
            this.settings.callbacks.error = data;
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (functionCheck('pagination', data)) {
            this.settings.callbacks.pagination = data;
        }
        return this;
    };
 
    //
    // Group Data - Required
    //
    
    this.name = function(data) {
        this.rData.requiredData.name = data;
        return this;
    };

    //
    // Group Data - Optional
    //
    this.attributes = function(data) {
        // if (!this.rData.optionalData.attribute) {this.rData.optionalData.attribute = []}
        if (objectCheck('attributes', data) && data.length != 0) {
            this.rData.optionalData.attribute.push(this.rData.optionalData.attribute, data);
        }
        return this;
    };
    
    this.tags = function(data) {
        if (this.rData.optionalData.tag) {this.rData.optionalData.tag = []}
        var tag;
        if (objectCheck('tag', data) && data.length != 0) {
            for (tag in data) {
                this.rData.optionalData.tag.push({name: data[tag]});
            }
        }
        return this;
    };
    
    //
    // Type Specific
    //
    
    // document
    this.fileName = function(data) {
        this.rData.specificData.document.fileName = data;
        return this;
    };
 
    this.fileSize = function(data) {
        this.rData.specificData.document.fileSize = data;
        return this;
    };
    
    // email
    this.emailBody = function(data) {
        this.rData.specificData.email.body = data;
        return this;
    };
 
    this.emailFrom = function(data) {
        this.rData.specificData.email.from = data;
        return this;
    };
 
    this.emailHeader = function(data) {
        this.rData.specificData.email.header = data;
        return this;
    };
 
    this.emailScore = function(data) {
        this.rData.specificData.email.score = data;
        return this;
    };
 
    this.emailSubject = function(data) {
        this.rData.specificData.email.subject = data;
        return this;
    };
 
    this.emailTo = function(data) {
        this.rData.specificData.email.to = data;
        return this;
    };
    
    //
    // Group Process
    //
    this.commit = function() {
        var _this = this;
        
        // validate required fields
        if (this.rData.requiredData.name && this.settings.api.owner) {
            var body,
                method = 'POST',
                requestUri = this.settings.api.requestUri,
                specificBody;
                
            // prepare body
            specificBody = this.rData.specificData[this.settings.api.type.dataField],
            body = $.extend(this.rData.requiredData, $.extend(this.rData.optionalData, specificBody));
            
            requestUri = [
                this.settings.api.requestUri,
                this.settings.api.requestUriType,
                this.settings.api.requestUriId
            ].join('/');
                
            if (this.settings.api.requestUriId) {
                method = 'PUT';
            }
            
            /* create job */ 
            var ro = new RequestObject();
            ro.owner(this.settings.api.owner)
                .activityLog(this.settings.api.activityLog)
                .body(body)
                .done(this.settings.callbacks.done)
                .error(this.settings.callbacks.error)
                .helper(true)
                .pagination(this.settings.callbacks.pagination)  // bcs - required for updates?
                .normalization(this.settings.api.normalizer)
                .requestUri(requestUri)
                .requestMethod(method)
                .type(this.settings.api.type);
            c.log('body', JSON.stringify(body, null, 4));
            this.apiRequest(ro);
                //.done(function(data) {
                // on done method commit attributes / tags
                // var ro = new RequestObject();
                // ro.owner(_this.settings.api.owner)
                //     .activityLog(_this.settings.api.activityLog)
                //     .body(body)
                //     .done(_this.settings.callbacks.done)
                //     .error(_this.settings.callbacks.error)
                //     .helper(true)
                //     // .pagination(_this.settings.callbacks.pagination)
                //     .normalization(_this.settings.api.cNormalizer)
                //     .requestUri(_this.settings.api.requestUri)
                //     .requestMethod('POST');
            // });
            
        } else {
            var errorMessage = 'Commit Failure: group name and owner are required.';
            console.error(errorMessage);
            this.settings.callbacks.error({error: errorMessage});
        } 
    };
    
    //
    // Delete Group
    //
    this.delete = function() {
        var requestUri = [
            this.settings.api.requestUri,
            this.settings.api.requestUriType,
            this.settings.api.requestUriId
        ].join('/');
        
        var ro = new RequestObject();
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .id(this.settings.api.requestUriId)
            .requestUri(requestUri)
            .requestMethod('DELETE')
            .resultLimit(this.settings.api.resultLimit)
            .type(this.settings.api.type);
        c.log('body', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        var requestUri = [
            this.settings.api.requestUri,
            this.settings.api.requestUriType,
            this.settings.api.requestUriId
        ].join('/');
        c.log('requestUri', requestUri);
            
        var ro = new RequestObject();
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .limit(this.settings.api.limit)
            .normalization(this.settings.api.normalizer)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod('GET')
            .resultLimit(this.settings.api.resultLimit)
            .type(this.settings.api.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    //
    // Retrieve Associations
    //
    this.retrieveAssociations = function(params) {
        // type: TYPE.GROUP
        c.log('params', params);
        var normalizer;
        if (params.type.type) {

            normalizer = normalize.find(params.type.type);
            /*
             if (params.type.type == 'Group') {
             normalizer = normalize.groups;
             } else if (params.type.type == 'Indicator') {
             normalizer = normalize.indicators;
             }
             */
        }
        
        var requestUri = [
            this.settings.api.requestUri,
            this.settings.api.requestUriType,
            this.settings.api.requestUriId,
            params.type.uri
        ].join('/');
        c.log('requestUri', requestUri);
            
        var ro = new RequestObject();
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(normalizer)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod('GET')
            .resultLimit(this.settings.api.resultLimit)
            .type(params.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    //
    // Retrieve Attributes
    //
    this.retrieveAttributes = function(params) {
        // type: TYPE.GROUP
        c.log('params', params);
        var normalizer = normalize.attributes;
        
        var requestUri = [
            this.settings.api.requestUri,
            this.settings.api.requestUriType,
            this.settings.api.requestUriId,
            'attributes'
        ].join('/');
        c.log('requestUri', requestUri);
            
        var ro = new RequestObject();
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(normalizer)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod('GET')
            .resultLimit(this.settings.api.resultLimit)
            .type(params.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    //
    // Retrieve Associations
    //
    this.retrieveTags = function(params) {
        // type: TYPE.GROUP
        c.log('params', params);
        var normalizer = normalize.tags;
        
        var requestUri = [
            this.settings.api.requestUri,
            this.settings.api.requestUriType,
            this.settings.api.requestUriId,
            'tags'
        ].join('/');
        c.log('requestUri', requestUri);
            
        var ro = new RequestObject();
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(normalizer)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod('GET')
            .resultLimit(this.settings.api.resultLimit)
            .type(params.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    c.groupEnd();
    return this;
}

//
// Indicators
//
function Indicators(threatconnect) {
    c.group('Indicators');
    ThreatConnect.call(this, threatconnect);
    
    this.batchBody = [],
    this.settings = {
        api: {
            activityLog: false,             // false|true
            limit: undefined,
            requestUriId: undefined,
            resultLimit: 500,
            owner: undefined,               // set twice due to batch
            type: TYPE.INDICATOR            // type constant
        },
        batch: {
            action: 'Create',               // Create|Delete
            attributeWriteType: 'Append',   // Append|Replace
            haltOnError: false,             // false|true
            owner: undefined,
        },
        status: {
            frequency: 1000,                // default: 1 second start
            timeout: 300000,                // default: 5 minutes
            multiplier: 2,                  // default: 2
            maxFrequency: 30000,            // deafult: 30 seconds
        },
        callbacks: {
            done: undefined,
            error: undefined,
            pagination: undefined,
        },
    },
    this.iData = {
        optionalData: {},
        requiredData: {},
        specificData: {
            Address: {},
            EmailAddress: {},
            File: {},
            Host: {},
            URL: {}
        },
    };
    
    //
    // Settings API
    //
    this.activityLog = function(data) {
        if (boolCheck('activityLog', data)) {
            this.settings.api.activityLog = data;
        }
        return this;
    };
    
    this.limit = function(data) {
        if (intCheck('limit', data)) {
            this.settings.api.limit = data;
        }
        return this;
    };
    
    this.resultLimit = function(data) {
        if (rangeCheck('resultLimit', data, 1, 500)) {
            this.settings.api.resultLimit = data;
        }
        return this;
    };
    
    //
    // Settings Batch
    //
    this.action = function(data) {
        if (valueCheck('action', data, ['Create', 'Delete'])) {
            this.settings.batch.haltOnError = data;
        }
        return this;
    };
    
    this.attributeWriteType = function(data) {
        if (valueCheck('attributeWriteType', data, ['Append', 'Replace'])) {
            this.settings.batch.haltOnError = data;
        }
        return this;
    };
                 
    this.haltOnError = function(data) {
        if (boolCheck('haltOnError', data)) {
            this.settings.batch.haltOnError = data;
        }
        return this;
    };
     
    this.owner = function(data) {
        this.settings.api.owner = data;  // set for retrieve
        this.settings.batch.owner = data;  // set for commit
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (functionCheck('done', data)) {
            this.settings.callbacks.done = data;
        }
        return this;
    };
    
    this.error = function(data) {
        if (functionCheck('error', data)) {
            this.settings.callbacks.error = data;
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (functionCheck('pagination', data)) {
            this.settings.callbacks.pagination = data;
        }
        return this;
    };
    
    //
    // Indicator Data - Required
    //
    this.indicator = function(data) {
        this.iData.requiredData.summary = data;
        return this;
    };
    
    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.api.type = data;
            this.iData.requiredData.type = data.type;
        }
        return this;
    };
    
    //
    // Indicator Data - Optional
    //
    
    // this.attribute = function(data) {
    //     if (!this.iData.optionalData.attribute) {this.iData.optionalData.attribute = []}
    //     if (typeof data === 'object' && data.length != 0) {
    //         this.iData.optionalData.attribute.push(data);
    //     } else {
    //         c.error('Tags must be an array.');
    //     }
    //     return this;
    // };
    
    this.attributes = function(data) {
        // if (!this.iData.optionalData.attribute) {this.iData.optionalData.attribute = []}
        // if (typeof data === 'object' && data.length != 0) {
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length != 0) {
            // this.iData.optionalData.attribute = $.merge(this.iData.optionalData.attribute, data);
            this.iData.optionalData.attribute = data;
        } else {
            c.error('Attributes must be an array.');
        }
        return this;
    };
    
    this.confidence = function(data) {
        if (intCheck('confidence', data)) {
            this.iData.optionalData.confidence = data;
        }
        return this;
    };
    
    this.description = function(data) {
        if (typeof data === 'string') {
            this.iData.optionalData.description = data;
        } else {
            c.error('Description must be a string.', data);
        }
        return this;
    };
    
    this.rating = function(data) {
        if (intCheck('rating', data)) {
            this.iData.optionalData.rating = data;
        } else {
            c.error('Rating must be a Float.', data);
        }
        return this;
    };
    
    // this.tag = function(data) {
    //     if (!this.iData.optionalData.tag) {this.iData.optionalData.tag = []}
    //     if (typeof data === 'string') {
    //         this.iData.optionalData.tag.push({name: data});
    //     } else {
    //         c.error('Tags must be a string.');
    //     }
    //     return this;
    // };
    
    this.tags = function(data) {
        var tag;
        // if (typeof data === 'object' && data.length != 0) {
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length != 0) {
            if (!this.iData.optionalData.tag) {this.iData.optionalData.tag = []}
            for (tag in data) {
                this.iData.optionalData.tag.push({name: data[tag]});
            }
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    //
    // Indicator Data - File Specific
    //
    
    this.description = function(data) {
        this.iData.specificData.File.description = data;
        return this;
    };
    
    //
    // Indicator Data - Host Specific
    //
    
    this.dnsActive = function(data) {
        if (boolCheck('dnsActive', data)) {
            this.iData.specificData.Host.dnsActive = data;
        }
        return this;
    };
    
    this.whoisActive = function(data) {
        if (boolCheck('whoisActive', data)) {
            this.iData.specificData.Host.whoisActive = data;
        }
        return this;
    };
    
    //
    // Indicator Data - Url Specific
    //
    
    this.source = function(data) {
        this.iData.specificData.URL.source = data;
        return this;
    };
    
    // Indicator Add (Batch)
    this.add = function() {
        var body = {},
            specificBody = {};
        
        if (this.iData.requiredData.summary && this.iData.requiredData.type) {
            // this.iData.optionalData[this.settings.type.postField] = this.settings.indicator;
            // this.iData.optionalData['summary'] = this.settings.indicator;
            // this.iData.optionalData['type'] = this.settings.type.type;
            body = $.extend(this.iData.requiredData, this.iData.optionalData);
            
            specificBody = this.iData.specificData[this.iData.requiredData.type],
                body = $.extend(body, specificBody);
                
            this.batchBody.push(body);
            
            this.iData.optionalData = {};
            this.iData.requiredData = {};
            this.iData.specificData = {};
        } else {
            console.error('Add Failure: indicator and type are required fields.');
        }
        return this;
    };
    
    // Indicator Commit to API
    this.commit = function() {
        var _this = this,
            message;
        
        // validate required fields
        if (this.settings.batch.owner && this.batchBody.length != 0) {
            c.log('this.settings.batch', JSON.stringify(this.settings.batch, null, 4));
            
            /* create job */ 
            var ro = new RequestObject();
            ro.helper(true)
                .activityLog(this.settings.api.activityLog)
                .async(false)
                .body(this.settings.batch)
                .error(this.settings.callbacks.error)
                .normalization(normalize.default)
                .requestUri('v2/batch')
                .requestMethod('POST');
                
            // create job
            this.apiRequest(ro)
                .done(function(jobResponse) {
                    _this.batchId = jobResponse.data.batchId;
                    var ro = new RequestObject();
                    ro.helper(true)
                        .activityLog(_this.settings.api.activityLog)
                        .async(false)
                        .body(_this.batchBody)
                        .contentType('application/octet-stream')
                        .error(_this.settings.callbacks.error)
                        .normalization(normalize.default)
                        .requestUri('v2/batch/' + jobResponse.data.batchId)
                        .requestMethod('POST');
                        
                    // post data
                    _this.apiRequest(ro)
                        .done(function(dataResponse) {
                            var ro = new RequestObject();
                            ro.helper(true)
                                .activityLog(_this.settings.api.activityLog)
                                .async(false)
                                .error(_this.settings.callbacks.error)
                                .normalization(normalize.default)
                                .requestUri('v2/batch/' + _this.batchId)
                                .requestMethod('GET');
                            var checkStatus = function() {
                                setTimeout(function() {
                                    console.log('status.frequency', _this.settings.status.frequency);
                                    console.log('status.timeout', _this.settings.status.timeout);
                                    
                                    // check status
                                    _this.apiRequest(ro)
                                        .done(function(statusResponse) {
                                            if (statusResponse.data.batchStatus.status == 'Completed') {
                                                statusResponse.data.batchStatus.data = _this.batchBody;
                                                if (statusResponse.data.batchStatus.errorCount > 0) {
                                                    var ro = new RequestObject();
                                                    ro.helper(true)
                                                        .activityLog(_this.settings.api.activityLog)
                                                        .async(false)
                                                        .normalization(normalize.default)
                                                        .requestUri('v2/batch/' + _this.batchId + '/errors')
                                                        .requestMethod('GET');
                                                        
                                                        // get errors
                                                        _this.apiRequest(ro)
                                                            .done(function(errorResponse) {
                                                                statusResponse.data.batchStatus.errors = JSON.parse(errorResponse);
                                                                _this.settings.callbacks.done(statusResponse.data.batchStatus);
                                                            });
                                                } else {
                                                    _this.settings.callbacks.done(statusResponse.data.batchStatus);
                                                }
                                            } else if (_this.settings.status.timeout <= 0) {
                                                _this.settings.callbacks.error({
                                                     error: 'Status check reach timeout value.'
                                                });
                                            } else {
                                                checkStatus();
                                            }
                                        });
                                }, _this.settings.status.frequency);
                                _this.updateFrequency(_this.settings.status);
                            };
                            checkStatus();
                        });
                })
                .fail(function() {
                    message = {error: 'Failed to configure indicator job.'};
                    _this.settings.callbacks.error(message);
                });
        } else {
            console.error('Commit Failure: batch owner and indicators are required.');
        } 
        
        return this;
    };
    
    // this.getData = function(params) {
    //     return this.batchBody;
    // };
    
    this.retrieve = function() {
        var requestUri = 'v2',
            method = 'GET';
        
        if (this.settings.api.type) {
            requestUri += '/' + this.settings.api.type.uri;
            if (this.iData.requiredData.summary) {
                requestUri += '/' + this.iData.requiredData.summary;
            }
        }
     
        var ro = new RequestObject();
        ro.helper(true)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .limit(this.settings.api.limit)
            .normalization(normalize.indicators)
            .owner(this.settings.api.owner)
            .pagination(this.settings.callbacks.pagination)
            .requestMethod(method)
            .requestUri(requestUri)
            .resultLimit(this.settings.api.resultLimit)
            .type(this.settings.api.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        // reset
        // this.batchBody = [];
        this.iData.optionalData = {};
        this.iData.requiredData = {};
        this.iData.specificData = {};
        
        this.settings.callbacks.done = undefined;
        this.settings.callbacks.pagination = undefined;
        this.settings.callbacks.error = undefined;
        
        return this;
    };
    
    this.retrieveAssociations = function(params) {
        // /v2/indicators/<indicator type>/<value>/groups
        
        c.log('params', params);
        var normalizer,
            requestUri = 'v2/indicators',
            method = 'GET';
            
        if (params.type.type) {
            normalizer = normalize.find(params.type.type);
            /*
            if (params.type.type == 'Group') {
                normalizer = normalize.groups;
            } else if (params.type.type == 'Indicator') {
                normalizer = normalize.indicators;
            }
            */
        }
        
        var requestUri = [
            requestUri,
            this.settings.api.type.uri,
            this.iData.requiredData.summary,
            params.type.uri
        ].join('/');
        c.log('requestUri', requestUri);
        return;
        
        if (this.settings.api.type) {
            requestUri += '/' + this.settings.api.type.uri;
            if (this.iData.requiredData.summary) {
                requestUri += '/' + this.iData.requiredData.summary;
            }
        }
     
        var ro = new RequestObject();
        ro.helper(true)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .limit(this.settings.api.limit)
            .normalization(normalizer)
            .owner(this.settings.api.owner)
            .pagination(this.settings.callbacks.pagination)
            .requestMethod(method)
            .requestUri(requestUri)
            .resultLimit(this.settings.api.resultLimit)
            .type(this.settings.api.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        // clear
        // this.init();
        
        return this;
    };
    
    this.init = function() {
        this.batchBody = [];
        this.iData = {
            optionalData: {},
            requiredData: {},
            specificData: {
                Address: {},
                EmailAddress: {},
                File: {},
                Host: {},
                URL: {}
            },
        };
        
        this.settings.callbacks.done = undefined;
        this.settings.callbacks.pagination = undefined;
        this.settings.callbacks.error = undefined;
    };
    
    this.updateFrequency = function(params) {
        if ((params.frequency * params.multiplier) < params.maxFrequency) {
            params.frequency = params.frequency * params.multiplier;
        } else {
            params.frequency = params.maxFrequency;
        }
        params.timeout -= params.frequency;
    };
    
    c.groupEnd();
    return this;
}
Indicators.prototype = Object.create(ThreatConnect.prototype);

//
// Owners
//
function Owners(threatconnect) {
    c.group('Owners');
    ThreatConnect.call(this, threatconnect);
    
    var ro = new RequestObject();
    this.settings = {
        api: {
            async: true,
            requestUri: 'v2/owners',
            resultLimit: 500
        },
        callbacks: {
            done: undefined,
            error: undefined,
            pagination: undefined,
        },
    },
    this.rData = {
        optionalData: {},
    };
 
    //
    // Settings API
    //
    this.async = function(data) {
        if (boolCheck('async', data)) { this.settings.api.aysnc = data; }
        return this;
    };
    
    
    this.resultLimit = function(data) {
        if (rangeCheck('resultLimit', data, 1, 500)) {
            this.settings.api.resultLimit = data;
        }
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (functionCheck('done', data)) {
            this.settings.callbacks.done = data;
        }
        return this;
    };
    
    this.error = function(data) {
        if (functionCheck('error', data)) {
            this.settings.callbacks.error = data;
        }
        return this;
    };
    
    // this.pagination = function(data) {
    //     if (functionCheck('pagination', data)) {
    //         this.settings.callbacks.pagination = data;
    //     }
    //     return this;
    // };
 
    //
    // Retrieve Group
    //
    this.retrieve = function(params) {
        if (params) {
            if (params.id) {
                this.settings.api.requestUri = this.settings.api.requestUri + '/' + params.id; 
            }
        }
        ro.helper(true)
            .async(this.settings.api.async)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .normalization(normalize.owners)
            .requestUri(this.settings.api.requestUri)
            .requestMethod('GET');
        this.apiRequest(ro);
        
        return this;
    };
    
    c.groupEnd();
    return this;
}
Owners.prototype = Object.create(ThreatConnect.prototype);

//
// Tags
//
function Tags(threatconnect) {
    c.group('Tags');
    ThreatConnect.call(this, threatconnect);
    
    var ro = new RequestObject();
    this.settings = {
        api: {
            activityLog: false,             // false|true
            owner: undefined,
            resultLimit: 500,
            requestUri: '/v2/tags'
        },
        callbacks: {
            done: undefined,
            error: undefined,
            pagination: undefined,
        },
    },
    this.rData = {
        optionalData: {},
    };
 
    //
    // Settings API
    //
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            this.settings.api.resultLimit = data;
        } else {
            console.warn('Invalid Result Count (' + data + ').');
        }
        return this;
    };
 
    this.owner = function(data) {
        this.settings.api.owner = data;
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (functionCheck('done', data)) {
            this.settings.callbacks.done = data;
        }
        return this;
    };
    
    this.error = function(data) {
        if (functionCheck('error', data)) {
            this.settings.callbacks.error = data;
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (functionCheck('pagination', data)) {
            this.settings.callbacks.pagination = data;
        }
        return this;
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function(params) {
        if (params) {
            if (params.id) {
                this.settings.api.requestUri = this.settings.api.requestUri + '/' + params.id; 
            }
        }
        ro.helper(true)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .normalization(normalize.tags)
            .owner(this.settings.api.owner)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(this.settings.api.requestUri)
            .requestMethod('GET');
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        return this;
    };
    
    c.groupEnd();
    return this;
}
Tags.prototype = Object.create(ThreatConnect.prototype);

//
// Attributes
//
function Attributes(threatconnect) {
    c.group('Attributes');
    ThreatConnect.call(this, threatconnect);
    
    var ro = new RequestObject();
    this.settings = {
        api: {
            activityLog: false,             // false|true
            owner: undefined,
            resultLimit: 500,
            requestUri: '/v2/attributes'
        },
        callbacks: {
            done: undefined,
            error: undefined,
            pagination: undefined,
        },
    },
    this.rData = {
        optionalData: {},
    };
 
    //
    // Settings API
    //
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            this.settings.api.resultLimit = data;
        } else {
            console.warn('Invalid Result Count (' + data + ').');
        }
        return this;
    };
 
    this.owner = function(data) {
        this.settings.api.owner = data;
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (functionCheck('done', data)) {
            this.settings.callbacks.done = data;
        }
        return this;
    };
    
    this.error = function(data) {
        if (functionCheck('error', data)) {
            this.settings.callbacks.error = data;
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (functionCheck('pagination', data)) {
            this.settings.callbacks.pagination = data;
        }
        return this;
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function(params) {
        if (params) {
            if (params.id) {
                this.settings.api.requestUri = this.settings.api.requestUri + '/' + params.id; 
            }
        }
        ro.helper(true)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .normalization(normalize.attributes)
            .owner(this.settings.api.owner)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(this.settings.api.requestUri)
            .requestMethod('GET');
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        return this;
    };
    
    c.groupEnd();
    return this;
}
Attributes.prototype = Object.create(ThreatConnect.prototype);


//
// Upload
//
ThreatConnect.prototype.upload = function() {
    c.group('upload');
    
    var ro = new RequestObject(),
        settings = {
            api: {
                activityLog: false,             // false|true
                method: 'GET',
                requestUri: 'v2/groups/documents',
                resultLimit: 500
            },
            callbacks: {
                done: undefined,
                error: undefined,
                pagination: undefined,
            },
        },
        rData = {
            optionalData: {},
            deleteData: {},
            requiredData: {},
            specificData: {},
        };
 
    //
    // Settings API
    //
    this.owner = function(data) {
        settings.api.owner = data;
        return this;
    };
 
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (typeof data === 'function') {
            settings.callbacks.done = data;
        } else {
            c.error('Callback "done()" must be a function.');
        }
        return this;
    };
    
    this.error = function(data) {
        if (typeof data === 'function') {
            settings.callbacks.error = data;
        } else {
            c.error('Callback "error()" must be a function.');
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (typeof data === 'function') {
            settings.callbacks.pagination = data;
        } else {
            c.error('Callback "pagination()" must be a function.');
        }
        return this;
    };
 
    //
    // Group Data - Required
    //
    
    this.body = function(data) {
        rData.requiredData.body = data;
        return this;
    };
    
    this.id = function(data) {
        rData.requiredData.id = data;
        return this;
    };
    
    //
    // Group Actions
    //
    
    this.commit = function() {
        // c.log('commit');
        
        // validate required fields
        if (rData.requiredData.body && settings.api.owner) {
            var uri = settings.api.requestUri + '/' + rData.requiredData.id + '/upload';
            
            /* create job */ 
            ro.owner(settings.api.owner)
                .body(rData.requiredData.body)
                .contentType('application/octet-stream')
                .done(settings.callbacks.done)
                .error(settings.callbacks.error)
                .helper(true)
                .normalization(normalize.default)
                .requestUri(uri)
                .requestMethod('POST');
            c.log('body', rData.requiredData.body);
            this.apiRequest(ro);
            
        } else {
            console.error('Commit Failure: Body is required.');
        } 
    };
    
    c.groupEnd();
    return this;
};

/*
 * Normalizers
 */
 
var normalize = {
    attributes: function(ro, response) { 
        c.group('normalize.attributes');
        var attributes = [],
            status = response.status;
        
        if (response) {
            attributes = response.data.attribute;
                
            if (Object.prototype.toString.call( attributes ) != '[object Array]') {
                attributes = [attributes];
            }
            c.log('attributes', attributes);
            
            ro.response.data = $.merge(ro.response.data, attributes);
            
            c.groupEnd();
        }
        return {status: status,
                data: attributes};
    },
    groups: function(ro, response) { 
        c.group('normalize.groups');
        var groups = [],
            status = response.status;
            
        if (response) {
            groups = response.data[ro._type.dataField];
            
            if (Object.prototype.toString.call( groups ) != '[object Array]') {
                if (groups.owner) {
                    groups.ownerName = groups.owner.name;
                    delete groups.owner;
                }
                groups = [groups];
            }
            
            ro.response.data = $.merge(ro.response.data, groups);
        }
        c.groupEnd();
        return {status: status,
                data: groups};
    },
    indicators: function(ro, response) { 
        c.group('normalize.indicators');
        var indicators,
            indicatorsData,
            indicatorTypeData,
            status = response.status;
        
        if (ro._type) {
            // indicatorTypeData = indicatorType(ro._type.charAt(0));
            indicatorTypeData = ro._type,
            response = response.data[ro._type.dataField];
            if (!response.length) {
                response = [response];
            }
        } else {
            response = response.data.indicator;
       }
        
        indicators = [];
        $.each( response, function( rkey, rvalue ) {
            // c.log('rvalue', rvalue);
            if ( rvalue && rvalue.length == 0 ) {
                return;
            }

            if ('type' in rvalue) {
                indicatorTypeData = indicatorHelper(rvalue.type.charAt(0).toLowerCase());
            }
            
            indicatorsData = [];
            $.each( indicatorTypeData.indicatorFields, function( ikey, ivalue ) {
                // change summary to proper field value
                // handle different types of hash
                
                if ('summary' in rvalue) {
                    indicatorsData.push(rvalue['summary']);
                    return false;
                } else {
                    if (rvalue[ivalue]) {
                        indicatorsData.push(rvalue[ivalue]);
                    }
                }
                // indicator: indicator.summary || indicator.ip || indicator.address
            });

            indicators.push({
                id: rvalue.id,
                indicators: indicatorsData.join(' : '),
                dateAdded: rvalue.dateAdded,
                lastModified: rvalue.lastModified,
                ownerName: rvalue.ownerName || rvalue.owner.name,
                rating: rvalue.rating,
                confidence: rvalue.confidence,
                type: indicatorTypeData.type,
                threatAssessRating: rvalue.threatAssessRating,
                threatAssessConfidence: rvalue.threatAssessConfidence,
                webLink: rvalue.webLink,
            });
        });
        ro.response.data = $.merge(ro.response.data, indicators);
        
        c.groupEnd();
        return {data: indicators,
                status: status};
    },
    owners: function(ro, response) { 
        c.group('normalize.owners');
        var owners = [],
            status = response.status;
        
        if (response) {
            owners = response.data.owner;
                
            if (Object.prototype.toString.call( owners ) != '[object Array]') {
                owners = [owners];
            }
            c.log('owners', owners);
            
            ro.response.data = $.merge(ro.response.data, owners);
            
            c.groupEnd();
        }
        return {status: status,
                data: owners};
    },
    tags: function(ro, response) { 
        c.group('normalize.tags');
        var tags = [],
            status = response.status;
        
        if (response) {
            tags = response.data.tag;
                
            if (Object.prototype.toString.call( tags ) != '[object Array]') {
                tags = [tags];
            }
            c.log('tags', tags);
            
            ro.response.data = $.merge(ro.response.data, tags);
            
            c.groupEnd();
        }
        return {status: status,
                data: tags};
    },
    default: function(ro, response) {
        c.group('normalize.default');
        c.log('response', response);
        ro.response.data = $.merge(ro.response.data, response);
        c.groupEnd();
        return response;
    },
    find: function(type) {

        switch (type) {
            case TYPE.GROUP.type:
            case TYPE.ADVERSARY.type:
            case TYPE.EMAIL.type:
            case TYPE.INCIDENT.type:
            case TYPE.SIGNATURE.type:
            case TYPE.THREAT.type:
                return this.groups;

            case TYPE.INDICATOR.type:
            case TYPE.ADDRESS.type:
            case TYPE.EMAIL_ADDRESS.type:
            case TYPE.FILE.type:
            case TYPE.HOST.type:
            case TYPE.URL.type:
                return this.indicators;
            default:
                c.warn('Invalid type provided.');
        }
    }
};

var boolCheck = function(name, value) {
    /* validate user input is a boolean */
    
    if (typeof value === 'boolean') {
        return true;
    }
    c.warn(name + ' must be of type boolean.');
    return false;
};

var functionCheck = function(name, value) {
    if (typeof value == 'function') {
        return true;
    }
    c.error(name + ' must be of type function.');
    return false;
};

var objectCheck = function(name, value) {
    if (typeof value == 'object') {
        return true;
    }
    c.error(name + ' must be of type object.');
    return false;
};

var intCheck = function(name, value) {
    /* validate user input is an integer */
    
    if (!isNaN(parseFloat(value))) {
        return true;
    }
    c.warn(name + ' must be of type integer.');
    return false;
};

var rangeCheck = function(name, value, low, high) {
    /* validate user input has appropriate values */
    if (!isNaN(value) && !isNaN(low) && !isNaN(high)) {
        if (low >= value <= high) {
            return true;
        }
    }
    c.warn(name + ' must be of type integer between ' + low + ' and ' + high + '.');
    return false;
};

var valueCheck = function(name, value, array) {
    if ($.inArray(value, array) != -1) {
        return true;
    }
    c.warn(name + ' must be of value (.' + array.join(',') + ').');
    return false;
};

var requiredCheck = function(name, data) {
    if (data[name]) {
        return true;
    }
    c.warn(name + ' paramater is required.');
    return false;
};