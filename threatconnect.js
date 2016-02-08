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
        'indicatorFields': ['summary'],
        'uri': 'indicators',
    },
    MD5: {
        'dataField': 'file',
        'postField': 'md5',
        'type': 'File',
        'uri': 'indicators/files',
    },
    OWNER: {
        'dataField': undefined,
        'type': 'Owner',
        'uri': 'owners',
    },
    SHA1: {
        'dataField': 'file',
        'postField': 'sha1',
        'type': 'File',
        'uri': 'indicators/files',
    },
    SHA256: {
        'dataField': 'file',
        'postField': 'sha256',
        'type': 'File',
        'uri': 'indicators/files',
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

// const FILTER = {  // ECMASCRIPT6 support only
var FILTER = {
    AND: 'and',
    EQ: '=',
    GT: '>',      /* %3E */
    // GE: '>=',  /* not currently supported */
    LT: '<',      /* %3C */
    // LE: '<=',  /* not currently supported */
    // NE: '!=',  /* not currently supported */
    OR: 'or',
    SW: '^'       /* %5E */
};

var indicatorHelper = function(prefix) {
    var iTypes = {
        'a': TYPE.ADDRESS,
        'e': TYPE.EMAIL_ADDRESS,
        'f': TYPE.FILE,
        'h': TYPE.HOST,
        'u': TYPE.URL
    };
    return iTypes[prefix];
};
    
function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(location.search);
        
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function getParameterArrayByName(name) {
	name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    
	var results = {};
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
    var result;
    var i = 0;
    
    var qs = location.search;
    
    while(result = regex.exec(qs)) {
    	results[i++] = (result === null ? "" : decodeURIComponent(result[1].replace(/\+/g, " ")));
    	qs = qs.substring(result.index + result[0].length);
    }
        
    return results;
}
    
function getParameterFromUri(name, uri) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(uri);
        
    return results === null ? undefined : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function Filter(param) {

    var separator = '',
        filters = '',
        orParams = false;

    if (param == FILTER.OR) {
        orParams = true;
    }

    this.on = function(field, operator, value) {
        filters += separator + field + operator + value;
        separator = ',';

        return this;
    };

    this.get = function() {
        return {
            filters: filters,
            orParams: orParams
        };
    };

    return this;
}

// var RequestObject = function() {
function RequestObject() {
    var _this = this;

    this.ajax = {
        async: true,
        baseUri: 'v2',
        body: undefined,
        contentType: 'application/json; charset=UTF-8',
        requestMethod: 'GET',
        requestUri: undefined,
    },
    this.authentication = {},
    this.callbacks = {
        done: undefined,
        error: undefined,
    },
    this.headers = {},
    this.payload = {
        // createActivityLog: 'false',
        // resultLimit: 500,
        // resultStart: 0
    },
    this.response = {
        apiCalls: 0,
        body: undefined,
        data: undefined,
        error: undefined,
        id: undefined,
        resultCount: 0,
        status: undefined,
    },
    this.settings = {
        helper: false,
        nextCount: 0,
        nextCountMax: 10,
        normalizer: normalize.default,
        normalizerType: undefined,
        pagination: false,
        previousCount: 0,
        previousCountMax: 10,
        remaining: 0,
        requestCount: 0,
        type: undefined,
        url: undefined,
    };
    
    /* secureProxy */
    /*
    this.secureProxy = function(url) {
        if (this.authentication.proxyServer) {
            return this.authentication.proxyServer + '/secureProxy?_targetUrl=' + encodeURIComponent(url);
        }
        return url;
    };
    */
    
    /* authentication */
    this.setAuthentication = function(data) {
        this.authentication = data;
        return this;
    };

    /* payload */
    this.addPayload = function(key, val) {
        // TODO: validate supported parameters
        this.payload[key] = val;
        return this;
    };
    
    this.removePayload = function(key) {
        if (key in this.payload) {
            delete this.payload[key];
        } 
        return this;
    };
    
    this.createActivityLog = function(data) {
        if (boolCheck('createActivityLog', data)) {
            this.addPayload('createActivityLog', data.toString());
        }
        return this;
    };

    this.filter = function(data) {
        if (this.payload.filters) delete this.payload.filters;
        if (this.payload.orParams) delete this.payload.orParams;
        this.addPayload('filters', data.get().filters);
        this.addPayload('orParams', data.get().orParams);
        return this;
    };

    this.modifiedSince = function(data) {
        this.addPayload('modifiedSince', data);
        return this;
    };
    
    this.owner = function(data) {
        this.addPayload('owner', data);
        return this;
    };
    
    this.resultLimit = function(data) {
        if (rangeCheck('resultLimit', data, 1, 500)) {
            this.addPayload('resultLimit', data);
            this.settings.requestCount = 500;  // bcs
        }
        return this;
    };
    
    this.resultStart = function(data) {
        this.addPayload('resultStart', data);
        return this;
    };
    
    /* headers */
    this.addHeader = function(key, val) {
        this.headers[key] = val;
        return this;
    };
    
    /* ajax settings */
    this.async = function(data) {
        if (boolCheck('async', data)) {
            this.ajax.async = data;
        }
        return this;
    };
    
    this.body = function(data) {
        this.ajax.body = JSON.stringify(data);
        this.response.body = JSON.stringify(data);
        if (data.id) {
            this.response.id = data.id;
        }
        return this;
    };
    
    this.contentType = function(data) {
        // TODO: validate content type
        this.ajax.contentType = data;
        return this;
    };
    
    this.requestMethod = function(method) {
        this.ajax.requestMethod = method;
        if (method == 'DELETE') {
            this.contentType(undefined);
        }
        return this;
    };
    
    this.requestUri = function(uri) {
        this.ajax.requestUri = uri;
        return this;
    };
    
    /* functions */
    this.done = function(data) {
        if (data) {
            if (functionCheck('done', data)) { this.callbacks.done = data; }
        }
        return this;
    };
    
    this.error = function(data) {
        if (data) {
            if (functionCheck('error', data)) { this.callbacks.error = data; }
        }
        return this;
    };
    
    this.normalization = function(method) {
        this.settings.normalizer = method;
        return this;
    };
    
    this.normalizationType = function(data) {
        this.settings.normalizerType = data;
        return this;
    };
    
    // this.go = function() {
    //     this.apiRequest({action: 'go'});
    // };
    
    this.hasNext = function() {
        if (this.settings.requestCount >= this.response.resultCount) {
            return false;
        }
        return true;
    };
    
    this.next = function() {
        this.settings.requestCount += this.payload.resultLimit;
        if (this.settings.pagination) {
            this.apiRequest({action: 'next'});
        } else {
            var nextInterval = setInterval(function() {
                if (_this.settings.pagination) {
                    _this.apiRequest({action: 'next'});
                    clearInterval(nextInterval);
                } else if (_this.settings.nextCount >= _this.settings.nextCountMax) {
                    clearInterval(nextInterval);
                    console.warn('Pagination is not enabled.');
                }
                _this.settings.nextCount++;
            }, 1000);
        }
        return this;
    };
    
    this.hasPrevious = function() {
        if (this.settings.requestCount == 0) {
            return false;
        }
        return true;
    };
    
    this.previous = function() {
        this.settings.requestCount += this.payload.resultLimit;
        if (this.settings.pagination) {
            this.apiRequest({action: 'previous'});
        } else {
            var previousInterval = setInterval(function() {
                if (_this.settings.pagination) {
                    _this.apiRequest({action: 'previous'});
                    clearInterval(previousInterval);
                } else if (_this.settings.previousCount >= _this.settings.previousCountMax) {
                    clearInterval(previousInterval);
                    console.warn('Pagination is not enabled.');
                }
                _this.settings.previousCount++;
            }, 1000);
        }
        return this;
    };
    
    /* response */
    this.data = function(data) {
        this.response.data = data;
        return this;
    };
    
    this.resultCount = function(data) {
        this.response.resultCount = data;
        return this;
    };
    
    this.remaining = function(data) {
        this.settings.remaining = data;
        return this;
    };
    
    //
    // api
    //
    this.apiHmacRequestHeader = function () {
        this._getTimestamp = function() {
            var date = new Date().getTime();
            return Math.floor(date / 1000);
        };
        
        var timestamp = this._getTimestamp(),
            signature = [this.settings.url.pathname + this.settings.url.search, this.ajax.requestMethod, timestamp].join(':'),
            hmacSignature = CryptoJS.HmacSHA256(signature, this.authentication.apiSec),
            authorization = 'TC ' + this.authentication.apiId + ':' + CryptoJS.enc.Base64.stringify(hmacSignature);
        console.log('timestamp', timestamp);
        console.log('signature', signature);
        console.log('hmacSignature', hmacSignature);
        console.log('authorization', authorization);
    
        this.addHeader('Timestamp', timestamp),
        this.addHeader('Authorization', authorization);
    };
    
    this.apiTokenRequestHeader = function () {
        this.addHeader('authorization', "TC-Token " + this.authentication.apiToken);
    };
    
    this.apiRequestUrl = function(host, pathname, search) {
        this.settings.url = document.createElement('a');
        this.settings.url.href =  this.authentication.apiUrl + '/' + this.ajax.requestUri;
        if (Object.keys(this.payload).length) {
            this.settings.url.href = this.settings.url.href + '?' + $.param(this.payload);
        }
    };
    
    this.apiRequest = function(params) {
        if (params.action == 'previous') {
            this.resultStart(this.payload.resultStart - (this.payload.resultLimit * 2));
            this.remaining(this.settings.remaining + (this.payload.resultLimit * 2));
        }
        
        this.apiRequestUrl();
            
        if (this.authentication.apiToken) {
            this.apiTokenRequestHeader();
        } else {
            this.apiHmacRequestHeader();
        }
        
        // if (this.payload.resultStart > this.response.resultCount) {
        //     console.warn('ResultStart cannot be greater than resultCount.');
        //     return;
        // }
            
        // jQuery ajax does not allow query string paramaters and body to
        // be used at the same time.  The url has to rebuilt manually.
        // first api call will always be synchronous to get resultCount
        var apiUrl = this.ajax.requestMethod === 'GET' ? [this.authentication.apiUrl, this.ajax.requestUri].join('/') : this.settings.url.href,
            defaults = {
            aysnc: false,
            url: this.ajax.requestMethod === 'GET' ? [this.authentication.apiUrl, this.ajax.requestUri].join('/') : this.settings.url.href,
            data: this.ajax.requestMethod === 'GET' ? this.payload : this.ajax.body,
            // data: this.ajax.requestMethod === 'GET' ? {} : this.ajax.body,
            headers: this.headers,
            crossDomain: false,
            method: this.ajax.requestMethod,
            contentType: this.ajax.contentType,
        };
        
        var apiPromise = $.ajax(defaults)
            .done(function (response, textStatus, request) {
                // console.log('request.getAllResponseHeaders()', request.getAllResponseHeaders());
                var currentCount = _this.settings.remaining,
                    // upload_pattern = /upload/,
                    remaining = undefined,
                    responseContentType = request.getResponseHeader('Content-Type');
                
                _this.response.apiCalls++;
                _this.response.status = response.status;
                
                if (response.status == 'Success' && response.data) {
                    if (response.data.resultCount) {
                        currentCount = response.data.resultCount;
                        _this.remaining(remaining);
                        _this.resultCount(response.data.resultCount);
                        _this.settings.pagination = true;
                    }
                    remaining = currentCount - _this.payload.resultLimit;
                    remaining = (remaining > 0) ? remaining : 0;
                    _this.remaining(remaining);

                    // var resultStart = getParameterFromUri('resultStart', this.url),
                    var normalizedData = _this.settings.normalizer(_this.settings.normalizerType, response.data),
                        doneResponse = $.extend({
                        // doneResponse = extend({
                            data: normalizedData,
                            remaining: remaining,
                            url: this.url
                        }, _this.response);
                    console.info('doneResponse', doneResponse);
                        
                    if (_this.callbacks.done) {
                        if (_this.settings.helper) {
                            _this.callbacks.done(doneResponse);
                        } else {
                            _this.callbacks.done(response);
                        }
                    }
                    
                } else if (responseContentType == 'application/octet-stream') {
                    // download
                    _this.response.data = response;
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                // } else if (upload_pattern.test(_this._requestUri)) {
                //     // upload helper 
                //     if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else if (_this.response.requestMethod === 'DELETE') {
                    // delete
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else if (response.status == 'Success') {
                    // upload
                    _this.response.body = undefined;  // bcs - remove because body of files can be large
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else if (responseContentType == 'application/json') {
                    // bulk download
                    _this.response.data = response;
                    
                    if (_this.callbacks.done) {
                        if (_this.settings.helper) {
                            _this.response.data = _this.settings.normalizer(_this.settings.normalizerType, response);
                            _this.callbacks.done(_this.response.data);
                        } else {
                            _this.callbacks.done(response);
                        }
                    }
                } else if (responseContentType == 'text/plain') {
                    // signature download
                    _this.response.data = response;
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else {
                    console.warn('Nothing to do with API Response.');
                }
            })
            .fail(function (response, textStatus, request) {
                _this.response.error = response.responseText;
                console.warn(response.responseText);
                
                if (_this.callbacks.error) {
                    _this.callbacks.error(_this.response);
                }
            });
            
        if (! this.payload.resultStart) this.resultStart(0);
        this.resultStart(this.payload.resultStart + this.payload.resultLimit);
        return apiPromise;
    };
    
    return this;
}

// var ThreatConnect = function(params) {
function ThreatConnect(params) {
    if (params.apiId && params.apiSec && params.apiUrl) {
        this.authentication = {
            'apiId': params.apiId,
            'apiSec': params.apiSec,
            'apiUrl': params.apiUrl,
            'proxyServer': undefined
        };
    } else if (params.apiToken && params.apiUrl) {
        this.authentication = {
            'apiToken': params.apiToken,
            'apiUrl': params.apiUrl,
            'proxyServer': params.proxyServer
        };
    } else {
        console.error('Required authentication parameters were not provided.');
        return false;
    }
    
    this.groups = function() {
        return new Groups(this.authentication);
    };
    
    this.indicators = function() {
        return new Indicators(this.authentication);
    };
    
    this.indicatorsBatch = function() {
        return new IndicatorsBatch(this.authentication);
    };
    
    this.owners = function() {
        return new Owners(this.authentication);
    };
    
    this.requestObject = function() {
        var ro = new RequestObject();
        ro.setAuthentication(this.authentication);
        return ro;
    };
    
    this.securityLabel = function() {
        return new SecurityLabels(this.authentication);
    };
    
    this.spaces = function() {
        return new Spaces(this.authentication);
    };

    this.tags = function() {
        return new Tags(this.authentication);
    };
}

function Groups(authentication) {
    RequestObject.call(this);
    
    this.authentication = authentication;
    this.ajax.requestUri = 'v2',
    this.resultLimit(500);
    this.settings.helper = true,
    this.settings.normalizer = normalize.groups,
    this.settings.type = TYPE.GROUP,
    this.rData = {
        id: undefined,
        associationType: undefined,
        associationId: undefined,
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
 
    /* SETTINGS API */
    this.id = function(data) {
        this.rData.id = data;
        this.response.id = data;
        return this;
    };

    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.type = data;
            this.settings.normalizerType = data;
        }
        return this;
    };
    
    this.associationId = function(data) {
        if (intCheck('associationId', data)) {
            this.rData.associationId = data;
        }
        return this;
    };

    this.associationType = function(data) {
        if (data.type && data.uri) {
            this.rData.associationType = data;
        }
        return this;
    };

    /* GROUP DATA REQUIRED */
    this.name = function(data) {
        this.rData.requiredData.name = data;
        return this;
    };

    /* GROUP DATA OPTIONAL */
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
    
    /* TYPE SPECIFIC PARAMETERS */
    
    // document / signature
    this.fileName = function(data) {
        this.rData.specificData.document.fileName = data;
        this.rData.specificData.signature.fileName = data;
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
    
    // incident
    this.eventDate = function(data) {
        this.rData.specificData.incident.eventDate = data;
        return this;
    };
    
    // signature
    this.fileType = function(data) {
        this.rData.specificData.signature.fileType = data;
        return this;
    };
    
    this.fileText = function(data) {
        this.rData.specificData.signature.fileText = data;
        return this;
    };
    
    /* API ACTIONS */
    
    // Commit
    this.commit = function(callback) {
        var _this = this;

        // validate required fields
        if (this.rData.requiredData.name) {

            // prepare body
            var specificBody = this.rData.specificData[this.settings.type.dataField];
            // this.body($.extend(this.rData.requiredData, $.extend(this.rData.optionalData, specificBody)));
            this.body(extend(this.rData.requiredData, extend(this.rData.optionalData, specificBody)));
            this.requestMethod('POST');

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id
            ].join('/'));

            if (this.rData.id) {
                this.requestMethod('PUT');
            }
            
            this.apiRequest({action: 'commit'})
                .done(function(response) {
                    _this.rData.id = response.data[_this.settings.type.dataField].id;
                    if (callback) callback();
                });
            
        } else {
            var errorMessage = 'Commit Failure: group name is required.';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        } 
    };
    
    // Commit Associations
    this.commitAssociation = function(association) {
        /* /v2/groups/<group type>/<group id>/groups/<group type>/<group id> */
        this.normalization(normalize.find(association.type.type));

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('associations');
    };
    
    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* /v2/groups/<group type>/<ID>/attributes */
        this.normalization(normalize.attributes);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes'
        ].join('/'));
        this.requestMethod('POST');
        this.body({
            type: attribute.type,
            value: attribute.value
        });
            
        this.apiRequest('attribute');
    };
    
    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* /v2/groups/<group type>/<ID>/securityLabel/<label> */
        this.normalization(normalize.securityLabels);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('securityLabel');
    };
    
    // Commit Tag
    this.commitTag = function(tag) {
        /* /v2/groups/<group type>/<ID>/tags/<tag> */
        this.normalization(normalize.tags);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('tag');
    };
    
    // Delete
    this.delete = function() {
        /* /v2/groups/<group type>/<ID> */
        
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));

        this.requestMethod('DELETE');
        this.apiRequest({action: 'delete'});
    };
 
    // Delete Associations
    this.deleteAssociation = function(association) {
        /* /v2/groups/<group type>/<group id>/groups/<group type>/<group id> */
        /* /v2/groups/<group type>/<group id>/indicators/<indicator type>/<indicator> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('associations');
    };
    
    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* /v2/groups/incidents/256/attributes/9 */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('attribute');
    };
    
    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* /v2/groups/<group type>/<ID>/securityLabel/<label> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('securityLabel');
    };
    
    // Delete Tag
    this.deleteTag = function(tag) {
        /* /v2/groups/<group type>/<ID>/tags/<tag> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('tag');
    };
    
    // Retrieve
    this.retrieve = function(callback) {
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));
        this.requestMethod('GET');
        this.settings.requestCount = this.payload.resultLimit;

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    // Retrieve Associations
    this.retrieveAssociations = function(association) {
        /* /v2/groups/adversaries/81/indicators */
        /* /v2/groups/adversaries/81/indicators/hosts */
        /* /v2/groups/adversaries/81/groups */
        /* /v2/groups/adversaries/81/groups/incidents */

        this.normalization(normalize.find(association.type.type));
        this.normalizationType(association.type);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
        ].join('/'));
        if (association.id) {
            this.requestUri([
                this.ajax.requestUri,
                association.id
            ].join('/'));
        }
            
        return this.apiRequest('associations');
    };
    
    // Retrieve Attributes
    this.retrieveAttributes = function(attributeId) {
        /* /v2/groups/<group type>/<ID>/attributes */
        this.settings.normalizer = normalize.attributes;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
        ].join('/'));
        if (intCheck('attributeId', attributeId)) {
            this.requestUri([
                this.ajax.requestUri,
                attributeId
            ].join('/'));
        }

        return this.apiRequest('attribute');
    };
    
    // Retrieve Tags
    this.retrieveTags = function() {
        /* /v2/groups/<group type>/<ID>/tags */
        this.settings.normalizer = normalize.tags;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags'
        ].join('/'));

        return this.apiRequest('tags');
    };
    
    // Retrieve Security Labels
    this.retrieveSecurityLabel = function() {
        /* /v2/groups/<group type>/<ID>/securityLabel */
        this.settings.normalizer = normalize.securityLabels;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels'
        ].join('/'));

        return this.apiRequest('securityLabel');
    };
    
    // Download
    this.download = function(params) {
        // this.contentType('application/octet-stream');
        this.requestMethod('GET');
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'download'
        ].join('/'));

        this.apiRequest({action: 'get'});
    };
    
    // Upload
    this.upload = function(params) {
        
        this.body(params.body);
        this.contentType('application/octet-stream');
        this.requestMethod('POST');
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'upload'
        ].join('/'));

        if (params.update) {
            this.requestMethod('PUT');
        }
        
        this.apiRequest({action: 'commit'});
        //    .done(function(response) {
        //        if (callback) callback();
        //    });
        
    };
    
    return this;
}
Groups.prototype = Object.create(RequestObject.prototype);

function Indicators(authentication) {
    RequestObject.call(this);
    
    this.authentication = authentication;
    this.settings.helper = true,
    this.settings.normalizer = normalize.indicators,
    this.settings.type = TYPE.INDICATOR,
    this.settings.normalizerType = TYPE.INDICATOR,
    this.iData = {
        indicator: undefined,
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
    
    /* INDICATOR SPECIFIC QUERY STRING PARAMETER */
    this.includeAdditional = function(data) {
        if (boolCheck('includeAdditional', data)) {
            this.addPayload('includeAdditional', data);
        }
        return this;
    };
    
    /* INDICATOR DATA REQUIRED */
    this.indicator = function(data) {
        this.iData.indicator = data;
        return this;
    };
    
    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.type = data;
            this.settings.normalizerType = data;
        }
        return this;
    };
    
    /* INDICATOR DATA OPTIONAL */
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
            console.error('Description must be a string.', data);
        }
        return this;
    };
    
    this.rating = function(data) {
        if (intCheck('rating', data)) {
            this.iData.optionalData.rating = data;
        }
        return this;
    };
    
    /* INDICATOR DATA SPECIFIC */
    
    // file
    this.description = function(data) {
        this.iData.specificData.File.description = data;
        return this;
    };
    
    // host
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
    
    // url
    this.source = function(data) {
        this.iData.specificData.URL.source = data;
        return this;
    };
    
    /* API ACTIONS */
    
    // Commit
    this.commit = function(callback) {
        // validate required fields
        if (this.iData.indicator) {
            
            this.iData.requiredData[this.settings.type.postField] = this.iData.indicator;

            // prepare body
            var specificBody = this.iData.specificData[this.settings.type.dataField];
            // this.body($.extend(this.iData.requiredData, $.extend(this.iData.optionalData, specificBody)));
            this.body(extend(this.iData.requiredData, extend(this.iData.optionalData, specificBody)));
            this.requestMethod('POST');

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                // this.iData.requiredData.summary
            ].join('/'));

            // if (this.rData.id) {
            //     this.requestMethod('PUT');
            // }
            
            this.apiRequest({action: 'commit'})
                .done(function(response) {
                    if (callback) callback();
                });
            
        } else {
            var errorMessage = 'Commit Failure: indicator is required.';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        } 
    };
    
    // Commit Associations
    this.commitAssociation = function(association) {
        /* /v2/indicators/<indicator type>/<indicator>/groups/incidents/199 */
        this.normalization(normalize.find(association.type.type));

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('associations');
    };
    
    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* /v2/indicators/<indicator type>/<indicator>/attributes */
        this.normalization(normalize.attributes);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'attributes'
        ].join('/'));
        this.requestMethod('POST');
        this.body({
            type: attribute.type,
            value: attribute.value
        });
            
        this.apiRequest('attribute');
    };
    
    // Commit False Positive
    this.commitFalsePositive = function(params) {
        /* /v2/indicators/<indicator type>/<indicator>/falsePositive */
        this.normalization(normalize.default);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'falsePositive'
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('falsePositive');
    };
    
    // Commit Occurrence
    this.commitObservation = function(params) {
        /* /v2/indicators/<indicator type>/<indicator>/observation */
        // this.normalization(normalize.observation);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'observations'
        ].join('/'));
        this.requestMethod('POST');
        this.body({
            count: params.count,
            dateObserved: params.dateObserved
        });
            
        this.apiRequest('attribute');
    };
    
    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* /v2/indicators/<indicator type>/<indicator>/securityLabel/<label> */
        this.normalization(normalize.securityLabels);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('securityLabel');
    };
    
    // Commit Tag
    this.commitTag = function(tag) {
        /* /v2/indicators/<indicator type>/<indicator>/tags/<tag> */
        this.normalization(normalize.tags);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');
            
        this.apiRequest('tag');
    };
    
    // Delete
    this.delete = function() {
        /* /v2/indicators/<indicator type>/<indicator> */
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.iData.indicator,
        ].join('/'));

        this.requestMethod('DELETE');
        this.apiRequest({action: 'delete'});
    };
 
    // Delete Associations
    this.deleteAssociation = function(association) {
        /* /v2/indicators/<indicator type>/<indicator>/groups/<group type>/<group id> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('associations');
    };
    
    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* /v2/indicators/<indicator type>/<indicator>/attributes/<attribute id> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('attribute');
    };
    
    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* /v2/indicators/<indicator type>/<indicator>/securityLabel/<label> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('securityLabel');
    };
    
    // Delete Tag
    this.deleteTag = function(tag) {
        /* /v2/indicators/<indicator type>/<indicator>/tags/<tag> */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');
            
        this.apiRequest('tag');
    };
    
    // retrieve
    this.retrieve = function(callback) {
        
        // this.ajax.requestUri += '/' + this.settings.type.uri;
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri
        ].join('/'));
        if (this.iData.indicator) {
            var indicator = this.iData.indicator;
            if (this.settings.type.type == 'URL') {
                indicator = encodeURIComponent(indicator);
            }
            this.ajax.requestUri += '/' + indicator;
        }
        this.settings.requestCount = this.payload.resultLimit;
        
        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    // retrieve associations
    this.retrieveAssociations = function(association) {
        /* /v2/indicators/<indicator type>/<value>/groups */
        /* /v2/indicators/<indicator type>/<value>/groups/adversaries */
        
        this.normalization(normalize.find(association.type.type));
        this.normalizationType(association.type);
        
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            association.type.uri,
        ].join('/'));
        if (association.id) {
            this.requestUri([
                this.ajax.requestUri,
                association.id
            ].join('/'));
        }
            
        return this.apiRequest('associations');
    };
    
    // Retrieve Attributes
    this.retrieveAttributes = function(attributeId) {
        /* /v2/indicators/<indicators type>/<indicator>/attributes */
        this.settings.normalizer = normalize.attributes;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'attributes',
        ].join('/'));
        if (intCheck('attributeId', attributeId)) {
            this.requestUri([
                this.ajax.requestUri,
                attributeId
            ].join('/'));
        }

        return this.apiRequest('attribute');
    };
    
    // Retrieve Observations
    this.retrieveObservations = function(attributeId) {
        /* /v2/indicators/<indicators type>/<indicator>/observations */
        this.settings.normalizer = normalize.observations;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'observations',
        ].join('/'));

        return this.apiRequest('observations');
    };
    
    // Retrieve ObservationCount
    this.retrieveObservationCount = function(attributeId) {
        /* /v2/indicators/<indicators type>/<indicator>/observationCount */
        this.settings.normalizer = normalize.observationCount;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'observationCount',
        ].join('/'));

        return this.apiRequest('observationCount');
    };
    
    // Retrieve Security Labels
    this.retrieveSecurityLabel = function() {
        /* /v2/indicators/<indicators type>/<indicator>/securityLabel */
        this.settings.normalizer = normalize.securityLabels;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'securityLabels'
        ].join('/'));

        return this.apiRequest('securityLabel');
    };
    
    // Retrieve Tags
    this.retrieveTags = function() {
        /* /v2/indicators/<indicators type>/<indicator>/tags */
        this.settings.normalizer = normalize.tags;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'tags'
        ].join('/'));

        return this.apiRequest('tags');
    };
    
    // dnsResolutions
    this.dnsResolutions = function() {
        /* /v2/indicators/hosts/<hostname>/dnsResolutions */
        if (this.settings.type == TYPE.HOST) {
            this.settings.normalizer = normalize.dnsResolutions;
    
            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.iData.indicator,
                'dnsResolutions'
            ].join('/'));
    
            return this.apiRequest('dnsResolutions');
        } else {
            this.callbacks.error('This method is only supported for Host Indicators.');
        }
    };
    
    // fileOccurrences
    this.fileOccurrences = function() {
        /* /v2/indicators/files/<hash>/fileOccurrences */
        if (this.settings.type == TYPE.FILE) {
            this.settings.normalizer = normalize.fileOccurrences;
    
            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.iData.indicator,
                'fileOccurrences'
            ].join('/'));
    
            return this.apiRequest('fileOccurrences');
        } else {
            this.callbacks.error('This method is only supported for File Indicators.');
        }
    };
    
    return this;
}
Indicators.prototype = Object.create(RequestObject.prototype);

function IndicatorsBatch(authentication) {
    RequestObject.call(this);
    
    this.authentication = authentication;
    this.batchBody = [],
    this.ajax.requestUri = 'v2',
    this.settings.helper = true,
    this.settings.normalizer = normalize.indicators,
    this.settings.type = TYPE.INDICATOR,
    this.settings.normalizerType = TYPE.INDICATOR,
    this.batch = {
        action: 'Create',               // Create|Delete
        attributeWriteType: 'Append',   // Append|Replace
        haltOnError: false,             // false|true
        owner: undefined,
    },
    this.status = {
        frequency: 1000,                // default: 1 second start
        timeout: 300000,                // default: 5 minutes
        multiplier: 2,                  // default: 2
        maxFrequency: 30000,            // deafult: 30 seconds
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
    
    /* SETTINGS BATCH */
    this.action = function(data) {
        if (valueCheck('action', data, ['Create', 'Delete'])) {
            this.batch.haltOnError = data;
        }
        return this;
    };
    
    this.attributeWriteType = function(data) {
        if (valueCheck('attributeWriteType', data, ['Append', 'Replace'])) {
            this.batch.haltOnError = data;
        }
        return this;
    };
                 
    this.haltOnError = function(data) {
        if (boolCheck('haltOnError', data)) {
            this.batch.haltOnError = data;
        }
        return this;
    };
     
    /* INDICATOR DATA REQUIRED */
    this.indicator = function(data) {
        this.iData.requiredData.summary = data;
        return this;
    };
    
    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.type = data;
            this.settings.normalizerType = data;
            this.iData.requiredData.type = data.type;
        }
        return this;
    };
    
    /* INDICATOR DATA OPTIONAL */
    this.attributes = function(data) {
        // if (!this.iData.optionalData.attribute) {this.iData.optionalData.attribute = []}
        // if (typeof data === 'object' && data.length != 0) {
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length != 0) {
            // this.iData.optionalData.attribute = $.merge(this.iData.optionalData.attribute, data);
            this.iData.optionalData.attribute = data;
        } else {
            console.error('Attributes must be an array.');
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
            console.error('Description must be a string.', data);
        }
        return this;
    };
    
    this.rating = function(data) {
        if (intCheck('rating', data)) {
            this.iData.optionalData.rating = data;
        } else {
            console.error('Rating must be a Float.', data);
        }
        return this;
    };
    
    this.tags = function(data) {
        var tag;
        // if (typeof data === 'object' && data.length != 0) {
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length != 0) {
            if (!this.iData.optionalData.tag) {this.iData.optionalData.tag = []}
            for (tag in data) {
                this.iData.optionalData.tag.push({name: data[tag]});
            }
        } else {
            console.error('Tags must be an array.');
        }
        return this;
    };
    
    /* INDICATOR DATA SPECIFIC */
    
    // file
    this.description = function(data) {
        this.iData.specificData.File.description = data;
        return this;
    };
    
    // host
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
    
    // url
    this.source = function(data) {
        this.iData.specificData.URL.source = data;
        return this;
    };
    
    /* BATCH */
    
    // add
    this.add = function() {
        var body = {},
            specificBody = {};
        
        if (this.iData.requiredData.summary && this.iData.requiredData.type) {
            // body = $.extend(this.iData.requiredData, this.iData.optionalData);
            body = extend(this.iData.requiredData, this.iData.optionalData);
            
            specificBody = this.iData.specificData[this.iData.requiredData.type],
                body = extend(body, specificBody);
                // body = $.extend(body, specificBody);
                
            this.batchBody.push(body);
            
            this.iData.optionalData = {};
            this.iData.requiredData = {};
            this.iData.specificData = {};
        } else {
            console.error('Add Failure: indicator and type are required fields.');
        }
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
    
    /* API ACTIONS */
    
    // commit
    this.commit = function() {
        var _this = this,
            message;
            
        // validate required fields
        if (this.payload.owner && this.batchBody.length != 0) {
            
            // this.body($.extend({owner: this.payload.owner}, this.batch));
            this.body(extend({owner: this.payload.owner}, this.batch));
            this.normalization(normalize.default);  // bcs rename
            this.requestUri(this.ajax.baseUri + '/batch');
            this.requestMethod('POST');
            this.done = this.callbacks.done;
            this.callbacks.done = undefined;
            
            /* create job */ 
            this.apiRequest({action: 'commit'})
                .done(function(jobResponse) {
                    _this.batchId = jobResponse.data.batchId;
                    
                    _this.body(_this.batchBody);
                    _this.contentType('application/octet-stream');
                    _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId);
                        
                    /* post data */
                    _this.apiRequest({action: 'commit'})
                        .done(function(dataResponse) {
                            
                            _this.body(_this.batchBody);
                            _this.contentType('application/octet-stream');
                            _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId);
                            _this.requestMethod('GET');
                            
                            var checkStatus = function() {
                                setTimeout(function() {
                                    console.log('status.frequency', _this.status.frequency);
                                    console.log('status.timeout', _this.status.timeout);
                                    
                                    /* get status */
                                    _this.apiRequest({action: 'status'})
                                        .done(function(statusResponse) {
                                                    
                                            if (statusResponse.data.batchStatus.status == 'Completed') {
                                                statusResponse.data.batchStatus.data = _this.batchBody;
                                                if (statusResponse.data.batchStatus.errorCount > 0) {
                                                    
                                                    _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId + '/errors/');
                                                    _this.requestMethod('GET');
                                                                
                                                    /* get errors */
                                                    _this.apiRequest({action: 'status'})
                                                        .done(function(errorResponse) {
                                                                    
                                                            if(typeof errorResponse === "string") {
                                                            	statusResponse.data.batchStatus.errors = JSON.parse(errorResponse);
                                                            } else {
                                                            	statusResponse.data.batchStatus.errors = errorResponse;
                                                            }
                                                            _this.done(statusResponse.data.batchStatus);
                                                        });
                                                } else {
                                                    _this.done(statusResponse.data.batchStatus);
                                                }
                                            } else if (_this.status.timeout <= 0) {
                                                _this.callbacks.error({
                                                     error: 'Status check reach timeout value.'
                                                });
                                            } else {
                                                checkStatus();
                                            }
                                        });
                                    }, _this.status.frequency);
                                _this.updateFrequency(_this.status);
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
    
    // retrieve
    this.retrieve = function(format) {
        this.requestUri(this.ajax.baseUri + '/indicators/bulk/' + format);
        this.normalization(normalize.indicatorsBatch);
        return this.apiRequest('next');
    };
    
    // retrieve batch status
    this.retrieveBatchStatus = function() {
        this.normalization(normalize.default);
        this.requestUri(this.ajax.baseUri + '/indicators/bulk');
        return this.apiRequest('next');
    };
    
    return this;
}
IndicatorsBatch.prototype = Object.create(RequestObject.prototype);

function Owners(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/owners',
    this.settings.helper = true,
    this.settings.normalizer = normalize.owners,
    this.settings.type = TYPE.OWNER,
    this.rData = {
        id: undefined,
        optionalData: {},
    };

    /* OPTIONAL */
    this.id = function(data) {
        if (intCheck('id', data)) {
            this.rData.id = data;
        }
        return this;
    };

    /* API ACTIONS */
    
    // Retrieve Owners
    this.retrieve = function(callback) {
        if (this.rData.id) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.id);
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };

    // Retrieve Owners Metrics
    this.retrieveMetrics = function() {
        if (this.rData.id) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.id);
        }
        this.requestUri(this.ajax.requestUri + '/metrics');
        this.requestMethod('GET');
        this.settings.normalizer = normalize.default;

        // return this.apiRequest('next').done(function() {
        //     if (callback) {
        //         callback();
        //     }
        // });
        
        return this.apiRequest('owner');
    };

    return this;
}
Owners.prototype = Object.create(RequestObject.prototype);

function Spaces(authentication) {
    RequestObject.call(this);
    
    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/owners',
    this.settings.helper = true,
    this.settings.normalizer = normalize.owners,
    this.settings.type = TYPE.OWNER,
    this.sData = {
        stateParams: {},
        stateText: {},
    };

    /* OPTIONAL */
    
    // state optional
    this.stateParams = function(data) {
        this.sData.stateParams = data;
        return this;
    };
    
    // state optional
    this.expireDays = function(data) {
        // this.sData.expireDays = data;
        this.addPayload('expireDays', data);
        return this;
    };
    
    /* REQUIRED */
    
    // state required
    this.stateText = function(data) {
        this.sData.stateText = data;
        return this;
    };

    /* API ACTIONS */
    
    // retrieve file
    this.retrieveFile = function(fileName) {
        /* GET - /v2/exchange/spaces/<element id>/file */
        /* GET - /v2/exchange/spaces/<element id>/file/<fileName> */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/state'
        ].join('/'));
        if (fileName) {
            this.requestUri([
                this.ajax.requestUri,
                fileName
            ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('file');
    };
    
    // retrieve job
    this.retrieveJob = function() {
        /* GET - /v2/exchange/spaces/<element id>/job */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/job'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('state');
    };
    
    // retrieve state
    this.retrieveState = function() {
        /* GET - /v2/exchange/spaces/<element id>/state */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/state'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('state');
    };
    
    // commit file
    this.commitFile = function(fileName) {
        /* POST - /v2/exchange/spaces/<element id>/file/<fileName> */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/state',
            fileName
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('file');
    };
    
    // commit job
    this.commitJob = function() {
        /* POST - /v2/exchange/spaces/<element id>/job */
        /* POST - /v2/exchange/spaces/<element id>/job/execute */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/job'
        ].join('/'));
        // var post = $.extend(this.sData.stateParams, this.sData.stateText);
        var post = extend(this.sData.stateParams, this.sData.stateText);
        this.body(post);
        this.requestMethod('POST');
        return this.apiRequest('state');
    };
    
    // commit state
    this.commitState = function() {
        /* POST - /v2/exchange/spaces/<element id>/state */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/state'
        ].join('/'));
        // var post = $.extend(this.sData.stateParams, this.sData.stateText);
        var post = extend(this.sData.stateParams, this.sData.stateText);
        this.body(post);
        this.requestMethod('POST');
        return this.apiRequest('state');
    };
    
    // delete file
    this.deleteFile = function(fileName) {
        /* DELETE - /v2/exchange/spaces/<element id>/file/<fileName> */
        
        this.requestUri([
            '/v2/exchange/spaces',
            this.elementId,
            '/state',
            fileName
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('file');
    };

    return this;
}
Spaces.prototype = Object.create(RequestObject.prototype);

function Tags(authentication) {
    RequestObject.call(this);
    /* /v2/tags */

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/tags',
    this.settings.helper = true,
    this.settings.normalizer = normalize.tags,
    this.settings.type = TYPE.TAG,
    this.rData = {
        name: undefined,
    };

    /* OPTIONAL */
    this.name = function(data) {
        this.rData.name = data;
        return this;
    };
    
    /* API ACTIONS */
    
    // retrieve
    this.retrieve = function(callback) {
        /* /v2/tags/<tag name> */
        
        if (this.rData.name) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.name);
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    return this;
}
Tags.prototype = Object.create(RequestObject.prototype);

function SecurityLabels(authentication) {
    RequestObject.call(this);
    /* /v2/attributes */

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/securityLabels',
    this.settings.helper = true,
    this.settings.normalizer = normalize.securityLabels,
    this.settings.type = TYPE.SECURITY_LABELS,
    this.rData = {
        name: undefined,
    };
    
    /* OPTIONAL */
    this.name = function(data) {
        this.rData.name = data;
        return this;
    };
    
    //
    // Retrieve Group
    //
    this.retrieve = function(callback) {
        if (this.rData.name) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.name);
        }
        this.requestMethod('GET');
     
        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    return this;
}
SecurityLabels.prototype = Object.create(RequestObject.prototype);

var normalize = {
    attributes: function(ro, response) { 
        var attributes = [];

        if (response) {
            attributes = response.attribute;
                
            if (Object.prototype.toString.call( attributes ) != '[object Array]') {
                attributes = [attributes];
            }
            
        }
        return attributes;
    },
    dnsResolutions: function(type, response) {
        // bcs - Complete this
        return response;
    },
    fileOccurrences: function(type, response) {
        // bcs - Complete this
        return response;
    },
    groups: function(type, response) {
        var groups = [];

        if (response) {
            if (type.dataField in response) {
                groups = response[type.dataField];
            } else if ('group' in response) {
                groups = response.group;
            }

            // if (Object.prototype.toString.call( groups ) != '[object Array]') {
            if (!groups.length) {
                if (groups.owner) {
                    groups.ownerName = groups.owner.name;
                    delete groups.owner;
                }
                groups = [groups];
            }
        }
        return groups;
    },
    indicators: function(type, response) { 
        var indicators,
            indicatorsData,
            indicatorType = type.type;


        if (type.dataField in response) {
            response = response[type.dataField];
        } else if ('indicator' in response) {
            response = response.indicator;
            type = TYPE.INDICATOR;
        }

        if (!response.length) {
            response = [response];
        }

        indicators = [];
        
        // $.each(response, function(rkey, rvalue) {
        Array.prototype.forEach.call(response, function(rvalue, index, array){
            if (rvalue && rvalue.length == 0) {
                return;
            }

            if ('type' in rvalue) {
                indicatorType = indicatorHelper(rvalue.type.charAt(0).toLowerCase()).type;
            }

            indicatorsData = [];
            // $.each(type.indicatorFields, function(ikey, ivalue) {
            Array.prototype.forEach.call(type.indicatorFields, function(ivalue, index, array){
                if ('summary' in rvalue) {
                    indicatorsData.push(rvalue['summary']);
                    return false;
                } else {
                    if (rvalue[ivalue]) {
                        indicatorsData.push(rvalue[ivalue]);
                    }
                }
            });

            indicators.push({
                id: rvalue.id,
                indicators: indicatorsData.join(' : '),
                dateAdded: rvalue.dateAdded,
                lastModified: rvalue.lastModified,
                ownerName: rvalue.ownerName || rvalue.owner.name,
                rating: rvalue.rating,
                confidence: rvalue.confidence,
                observationCount: rvalue.observationCount,
                falsePositiveCount: rvalue.falsePositiveCount,
                type: indicatorType,
                threatAssessRating: rvalue.threatAssessRating,
                threatAssessConfidence: rvalue.threatAssessConfidence,
                webLink: rvalue.webLink,
            });
        });
        
        return indicators;
    },
    indicatorsBatch: function(type, response) { 

        response = response.indicator;

        var indicators = [];
        // $.each(response, function(rkey, rvalue) {
        Array.prototype.forEach.call(response, function(rvalue, index, array){
            if (rvalue && rvalue.length == 0) {
                return;
            }

            rvalue.indicator = rvalue['summary'];
            delete rvalue.summary;

            indicators.push(rvalue);
        });
        
        return indicators;
    },
    observations: function(ro, response) { 
        var observations = [];

        if (response) {
            observations = response.observation;
                
            if (Object.prototype.toString.call( observations ) != '[object Array]') {
                observations = [observations];
            }
        }
        return observations;
    },
    observationCount: function(ro, response) { 
        var observationCount = undefined;

        if (response) {
            observationCount = response.observationCount;
        }
        return observationCount;
    },
    owners: function(type, response) {
        var owners = [];

        if (response) {
            owners = response.owner;
            if (Object.prototype.toString.call( owners ) != '[object Array]') {
                owners = [owners];
            }
        }
        return owners;
    },
    securityLabels: function(ro, response) { 
        var securityLabel = undefined;

        if (response) {
            securityLabel = response.securityLabel;
                
            // if (Object.prototype.toString.call( tags ) != '[object Array]') {
            //     tags = [tags];
            // }
        }
        return securityLabel;
    },
    tags: function(ro, response) { 
        var tags = [];

        if (response) {
            tags = response.tag;
                
            if (Object.prototype.toString.call( tags ) != '[object Array]') {
                tags = [tags];
            }
        }
        return tags;
    },
    default: function(type, response) {
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
                console.warn('Invalid type provided.');
        }
    }
};

var boolCheck = function(name, value) {
    /* validate user input is a boolean */
    
    if (typeof value === 'boolean') {
        return true;
    }
    console.warn(name + ' must be of type boolean.');
    return false;
};

var functionCheck = function(name, value) {
    if (typeof value == 'function') {
        return true;
    }
    console.error(name + ' must be of type function.');
    return false;
};

var objectCheck = function(name, value) {
    if (typeof value == 'object') {
        return true;
    }
    console.error(name + ' must be of type object.');
    return false;
};

var intCheck = function(name, value) {
    /* validate user input is an integer */
    
    if (!isNaN(parseFloat(value))) {
        return true;
    }
    console.warn(name + ' must be of type integer.');
    return false;
};

var rangeCheck = function(name, value, low, high) {
    /* validate user input has appropriate values */
    if (!isNaN(value) && !isNaN(low) && !isNaN(high)) {
        if (low >= value <= high) {
            return true;
        }
    }
    console.warn(name + ' must be of type integer between ' + low + ' and ' + high + '.');
    return false;
};

var valueCheck = function(name, value, array) {
    if ($.inArray(value, array) != -1) {
        return true;
    }
    console.warn(name + ' must be of value (.' + array.join(',') + ').');
    return false;
};

var requiredCheck = function(name, data) {
    if (data[name]) {
        return true;
    }
    console.warn(name + ' paramater is required.');
    return false;
};

var extend = function() {
    // Variables
    var extended = {};
    var deep = false;
    var i = 0;
    var length = arguments.length;

    // Check if a deep merge
    if (Object.prototype.toString.call(arguments[0]) === '[object Boolean]') {
        deep = arguments[0];
        i++;
    }

    // Merge the object into the extended object
    var merge = function(obj) {
        for (var prop in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, prop)) {
                // If deep merge and property is an object, merge properties
                if (deep && Object.prototype.toString.call(obj[prop]) === '[object Object]') {
                    extended[prop] = extend(true, extended[prop], obj[prop]);
                }
                else {
                    extended[prop] = obj[prop];
                }
            }
        }
    };

    // Loop through each object and conduct a merge
    for (; i < length; i++) {
        var obj = arguments[i];
        merge(obj);
    }
    return extended;
};