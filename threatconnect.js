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

/* global CryptoJS */

var c = console;

const TYPE = {
    ADDRESS: {
        'dataField': 'address',
        'postField': 'ip',
        'indicatorFields': ['ip'],
        'type': 'Address',
        'uri': 'addresses',
    },
    EMAIL_ADDRESS: {
        'dataField': 'emailAddress',
        'postField': 'address',
        'indicatorFields': ['address'],
        'type': 'EmailAddress',
        'uri': 'emailAddresses',
    },
    FILE: {
        'dataField': 'file',
        'postField': '',
        'indicatorFields': ['md5', 'sha1', 'sha256'],
        'type': 'File',
        'uri': 'files',
    },
    HOST: {
        'dataField': 'host',
        'postField': 'hostName',
        'indicatorFields': ['hostName'],
        'type': 'Host',
        'uri': 'hosts',
    },
    URL: {
        'dataField': 'url',
        'postField': 'text',
        'indicatorFields': ['text'],
        'type': 'URL',
        'uri': 'urls',
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

//
// Request Object
//
function RequestObject(params) {
    c.group('RequestObject');

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
    this._payload = {},
    this._remaining = 0,
    this._requestUri = undefined,
    this._resultCount = 0,
    this._resultLimit = 200,
    this._resultStart = 0,
    this._type = undefined,
    this.response = {
        body: undefined,
        data: [],
        error: undefined,
        id: undefined,
        requestMethod: 'GET',
        status: undefined,
    };

    this.payload = function(key, val) {
        this._payload[key] = val;
        return this;
    };
    
    this.addHeader = function(key, val) {
        this._headers[key] = val;
        return this;
    };
    
    this.activityLog = function(bool) {
        if (typeof data === 'boolean') {
            this.payload('createActivityLog', bool.toString());
        }
        return this;
    };
    
    this.async = function(data) {
        if (typeof data === 'boolean') {
            this._async = data;
        } else {
            c.error('async must be a boolean.');
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
        this._done = data;
        return this;
    };
    
    this.error = function(data) {
        this._error = data;
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
        this.limit = parseInt(data, 10);
        if (this.limit < 500 && this.limit > this._resultLimit) {
            this._resultLimit = this.limit;
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
    
    this.pagination = function(method) {
        this._pagination = method;
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
        this._resultCount = data;
        return this;
    };
    
    this.resultLimit = function(data) {
        if (parseInt(data, 10) <= 500) {
            if (this.limit < 500 && this.limit > parseInt(data, 10)) {
                this.payload('resultLimit', this._limi);
                this._resultLimit = this._limit;
            } else {
                this.payload('resultLimit', parseInt(data, 10));
                this._resultLimit = parseInt(data, 10);
            }
        } else {
            c.warn('The maximum value for resultLimit is 500.');
        }
        return this;
    };
    
    this.resultStart = function(start) {
        this.payload('resultStart', start);
        this._resultStart = start;
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
    if (!!((params.apiId && params.apiKey) || params.apiToken)) { return false; }
    
    this.apiId = params.apiId;
    this.apiSec = params.apiSec;
    this.apiToken = params.apiToken;
    this.apiUrl = (params.apiUrl ? params.apiUrl : 'https://api.threatconnect.com');
    // secondary restriction if browser does not limit concurrent api requests
    this.concurrentCalls = (params.concurrentCalls ? params.concurrentCalls : 10);
    
    this.apiHmacRequestHeader = function (ro) {
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
        c.log('url.href', url.href);
        c.log('defaults', defaults);
        
        c.groupEnd();
        // make first api call
        return $.ajax(defaults)
            // .always(function (response) {
            .done(function (response) {
                c.log('response', response);
                var upload_pattern = /upload/;
                
                if (ro._helper === false) {
                    ro._done(response);
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
                            .remaining(ro._resultCount - ro._resultLimit);
                            
                        // c.log('ro.resultCount', ro.resultCount);
                        // c.log('ro._remaining', ro._remaining);
                        
                        _this.apiRequestPagination(ro);
                    } else {
                        // callback for done
                        c.log('done apiRequest')
                        ro._done(ro.response);
                    }
                } else if (upload_pattern.test(ro._requestUri)) {
                    ro._done(ro.response);
                } else if (ro.response.requestMethod === 'DELETE') {
                    ro._done(ro.response);
                }
            })
            .fail(function (response) {
                c.log('fail response');
                ro.response.error = response.responseText;
                
                ro._error(ro.response);
            });
    };
    
    this.apiRequestPagination = function(ro) {
        var _this = this;
        c.group('apiRequestPagination');
                
        // stop processing if limit is reached
        if (ro.response.data.length >= ro._limit && ro._remaining <= 0) return;
        
        var ajaxRequests = [];
        for (var i=1;i<=this.concurrentCalls;i++) {
            c.log('ro._remaining', ro._remaining);
            
            if (ro._remaining <= 0) {
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
                // callback for paginated results
                if (typeof ro._pagination === 'function') {
                    ro._pagination(ro._normalizer(ro, response));
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
            if (ro._remaining > 0) {
                _this.apiRequestPagination(ro);
            } else {
                ro._done(ro.response);
            }
        });
        c.groupEnd();
    };
    
    this.adversaries = function() {
        return new Adversaries(this);
    };
    
    this.documents = function() {
        return new Documents(this);
    };
    
    this.emails = function() {
        return new Emails(this);
    };
    
    this.incidents = function() {
        return new Incidents(this);
    };
    
    this.indicators = function() {
        return new Indicators(this);
    };
    
    this.owners = function() {
        return new Owners(this);
    };
}

//
// Group
//

function Groups(threatconnect) {
    c.group('Group');
    ThreatConnect.call(this, threatconnect);
    
    var ro = new RequestObject();
    this.settings = {
        api: {
            activityLog: false,             // false|true
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
        deleteData: {},
        requiredData: {},
        specificData: {},
    };
 
    //
    // Settings API
    //
    this.activityLog = function(data) {
        // c.log('activityLog', data);
        if (typeof data === 'boolean') {
            this.settings.api.activityLog = data;
        } else {
            c.error('activityLog must be a boolean.');
        }
        return this;
    };
    
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
        if (typeof data === 'function') {
            this.settings.callbacks.done = data;
        } else {
            c.error('Callback "done()" must be a function.');
        }
        return this;
    };
    
    this.error = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.error = data;
        } else {
            c.error('Callback "error()" must be a function.');
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.pagination = data;
        } else {
            c.error('Callback "pagination()" must be a function.');
        }
        return this;
    };
 
    //
    // Group Data - Required
    //
    this.id = function(data) {
        this.rData.deleteData.id = data;
        return this;
    };
    
    this.name = function(data) {
        this.rData.requiredData.name = data;
        return this;
    };

    //
    // Group Data - Optional
    //
    this.attributes = function(data) {
        // if (!this.rData.optionalData.attribute) {this.rData.optionalData.attribute = []}
        if (typeof data === 'object' && data.length != 0) {
            this.rData.optionalData.attribute.push(this.rData.optionalData.attribute, data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.tags = function(data) {
        if (this.rData.optionalData.tag) {this.rData.optionalData.tag = []}
        var tag;
        if (typeof data === 'object' && data.length != 0) {
            for (tag in data) {
                this.rData.optionalData.tag.push({name: data[tag]});
            }
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    //
    // Group Process
    //
    this.commit = function() {
        var _this = this;
        // c.log('commit');
        
        // validate required fields
        if (this.rData.requiredData.name && this.settings.api.owner) {
            var body = $.extend(this.rData.requiredData, this.rData.optionalData);
            
            /* create job */ 
            ro.owner(this.settings.api.owner)
                .activityLog(this.settings.api.activityLog)
                .body(body)
                .done(this.settings.callbacks.done)
                .error(this.settings.callbacks.error)
                .helper(true)
                // .pagination(this.settings.callbacks.pagination)
                .normalization(this.settings.api.cNormalizer)
                .requestUri(this.settings.api.requestUri)
                .requestMethod('POST');
            c.log('body', JSON.stringify(body, null, 4));
            this.apiRequest(ro).done(function(data) {
                // on done method commit attributes / tags
                var ro = new RequestObject();
                ro.owner(_this.settings.api.owner)
                    .activityLog(_this.settings.api.activityLog)
                    .body(body)
                    .done(_this.settings.callbacks.done)
                    .error(_this.settings.callbacks.error)
                    .helper(true)
                    // .pagination(_this.settings.callbacks.pagination)
                    .normalization(this.settings.api.cNormalizer)
                    .requestUri(this.settings.api.requestUri)
                    .requestMethod('POST');
            });
            
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
        var uri = this.settings.api.requestUri + '/' + this.rData.deleteData.id;
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .id(this.rData.deleteData.id)
            .requestUri(uri)
            .requestMethod('DELETE')
            .resultLimit(this.settings.api.resultLimit);
            // .type(this.settings.data.type);
        c.log('body', ro);
     
        this.apiRequest(ro);
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
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(this.settings.api.rNormalizer)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(this.settings.api.requestUri)
            .requestMethod('GET')
            .resultLimit(this.settings.api.resultLimit);
            // .type(this.settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    this.getData = function(params) {
        return this.rData.requiredData;
    };
 
    c.groupEnd();
    return this;
}

//
// Adversaries
//
function Adversaries(threatconnect) {
    Groups.call(this, threatconnect);
    
    this.settings.api.requestUri = 'v2/groups/adversaries';
    this.settings.api.cNormalizer = normalize.adversaries;
    this.settings.api.rNormalizer = normalize.adversaries;
}
Adversaries.prototype = Object.create(Groups.prototype);

//
// Documents
//
function Documents(threatconnect) {
    Groups.call(this, threatconnect);
    
    this.settings.api.requestUri = 'v2/groups/documents';
    this.settings.api.cNormalizer = normalize.documents;
    this.settings.api.rNormalizer = normalize.documents;
    
    // Group Data - Required
    this.fileName = function(data) {
        this.rData.requiredData.fileName = data;
        return this;
    };
    
    // Group Data - Optional
    this.fileSize = function(data) {
        this.rData.optionalData.fileSize = data;
        return this;
    };
}
Documents.prototype = Object.create(Groups.prototype);

//
// Incidents
//
function Incidents(threatconnect) {
    Groups.call(this, threatconnect);
    
    this.settings.api.requestUri = 'v2/groups/incidents';
    this.settings.api.cNormalizer = normalize.incidents;
    this.settings.api.rNormalizer = normalize.incidents;
}
Incidents.prototype = Object.create(Groups.prototype);

//
// Emails
//
function Emails(threatconnect) {
    Groups.call(this, threatconnect);
    
    this.settings.api.requestUri = 'v2/groups/emails';
    this.settings.api.cNormalizer = normalize.emails;
    this.settings.api.rNormalizer = normalize.emails;
    
    // Group Data - Optional
    this.emailBody = function(data) {
        if (data.length > 0) {
           this.rData.optionalData.body = data;
        }
        return this;
    };
    
    // Group Data - Optional
    this.emailFrom = function(data) {
        if (data.length > 0) {
            this.rData.optionalData.from = data;
        }
        return this;
    };
    
    // Group Data - Optional
    this.emailHeader = function(data) {
        if (data.length > 0) {
            this.rData.optionalData.header = data;
        }
        return this;
    };
    
    // Group Data - Optional
    this.emailScore = function(data) {
        if (data.length > 0) {
            this.rData.optionalData.score = data;
        }
        return this;
    };
    
    // Group Data - Optional
    this.emailSubject = function(data) {
        if (data.length > 0) {
            this.rData.optionalData.subject = data;
        }
        return this;
    };
    
    // Group Data - Optional
    this.emailTo = function(data) {
        if (data.length > 0) {
            this.rData.optionalData.to = data;
        }
        return this;
    };
}
Emails.prototype = Object.create(Groups.prototype);


//
// Indicators
//
function Indicators(threatconnect) {
    c.group('add_indicator');
    Groups.call(this, threatconnect);
    
    this.batchBody = [],
    this.settings = {
        api: {
            activityLog: false,             // false|true
            // method: 'POST',
            // requestUri: 'v2/batch',
            resultLimit: 500,
        },
        batch: {
            action: 'Create',               // Create|Delete
            attributeWriteType: 'Append',   // Append|Replace
            haltOnError: false,             // false|true
            owner: undefined,
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
    var ro = new RequestObject();
    
    //
    // Settings API
    //
    this.activityLog = function(data) {
        // c.log('activityLog', data);
        if (typeof data === 'boolean') {
            this.settings.api.activityLog = data;
        } else {
            c.error('activityLog must be a boolean.');
        }
        return this;
    };
    
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            this.settings.api.resultLimit = data;
        } else {
            console.warn('Invalid Result Count (' + data + ').');
        }
        return this;
    };
    
    //
    // Settings Batch
    //
    this.action = function(data) {
        // c.log('action', data);
        if ($.inArray(data, ['Create', 'Delete']) != -1) {
            this.settings.batch.haltOnError = data;
        } else {
            c.error('Setting action must be of value (Create|Delete).');
        }
        return this;
    };
    
    this.attributeWriteType = function(data) {
        // c.log('attributeWriteType', data);
        if ($.inArray(data, ['Append', 'Replace']) != -1) {
            this.settings.batch.haltOnError = data;
        } else {
            c.error('Setting attributeWriteType must be of value (Append|Replace).');
        }
        return this;
    };
                
    this.haltOnError = function(data) {
        // c.log('haltOnError', data);
        if (typeof data === 'boolean') {
            this.settings.batch.haltOnError = data;
        } else {
            c.error('Setting haltOnError must be a boolean.');
        }
        return this;
    };
    
    this.owner = function(data) {
        // c.log('owner', data);
        if (typeof data === 'string') {
            this.settings.batch.owner = data;
        } else {
            c.error('Setting owner must be a string.');
        }
        return this;
    };
    
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.done = data;
        } else {
            c.error('Callback "done()" must be a function.');
        }
        return this;
    };
    
    this.error = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.error = data;
        } else {
            c.error('Callback "error()" must be a function.');
        }
        return this;
    };
    
    this.pagination = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.pagination = data;
        } else {
            c.error('Callback "pagination()" must be a function.');
        }
        return this;
    };
    
    //
    // Indicator Data - Required
    //
    this.indicator = function(data) {
        // c.log('indicator', data);
        this.iData.requiredData.summary = data;
        return this;
    };
    
    this.type = function(data) {
        // c.log('type', data.type);
        if (data.type && data.uri) {
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
        if (!isNaN(data)) {
            this.iData.optionalData.confidence = data;
        } else {
            c.error('Confidence must be an integer.', data);
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
        if (!isNaN(parseFloat(data))) {
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
    this.descrition = function(data) {
        this.iData.specificData.File.description = data;
        return this;
    };
    
    //
    // Indicator Data - Host Specific
    //
    this.dnsActive = function(data) {
        if (typeof data === 'boolean') {
            this.iData.specificData.Host.dnsActive = data;
        }
        return this;
    };
    
    this.whoisActive = function(data) {
        if (typeof data === 'boolean') {
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
        // c.log('commit');
        
        // validate required fields
        if (this.settings.batch.owner && this.batchBody.length != 0) {
            
            /* create job */ 
            ro.activityLog(this.settings.api.activityLog)
                .async(false)
                .body(this.settings.batch)
                .done(this.settings.callbacks.done)
                .error(this.settings.callbacks.error)
                .helper(true)
                .normalization(normalize.default)
                .requestUri('v2/batch')
                .requestMethod('POST');
            c.log('this.settings.batch', JSON.stringify(this.settings.batch, null, 4));
            // c.log('ro', JSON.stringify(ro, null, 4));
            
            this.apiRequest(ro)
                .done(function(prom) {
                    ro.activityLog(_this.settings.api.activityLog)
                        .body(_this.batchBody)
                        .contentType('application/octet-stream')
                        .done(_this.settings.callbacks.done)
                        .error(_this.settings.callbacks.error)
                        .helper(true)
                        .normalization(normalize.default)
                        .requestUri('v2/batch/' + prom.data.batchId)
                        .requestMethod('POST');
                    c.log('_this.batchBody', JSON.stringify(_this.batchBody, null, 4));
                    c.log('done ro', ro);
                    _this.apiRequest(ro);
                    
                    // reset
                    // _this.batchBody = [];
                    // _this.iData.optionalData = {};
                    // _this.iData.requiredData = {};
                    // _this.iData.specificData = {};
                })
                .fail(function() {
                    message = {error: 'Failed to configure indicator job.'};
                    _this.settings.callbacks.error(message);
                });
            
        } else {
            console.error('Commit Failure: batch owner and indicators are required.');
        } 
    };
    
    this.getData = function(params) {
        return this.batchBody;
    };
    
    this.retrieve = function(params) {
        var requestUri = 'v2/indicators',
            method = 'GET',
            type = undefined;
        
        if (params) {
            if (params.type) {
                type = params.type;
                if (params.type.type && params.type.uri) {
                    requestUri = [requestUri, params.type.uri].join('/');
         
                    if (params.indicator) {
                        requestUri = [requestUri, params.indicator].join('/');
                    }
                }
            }
        }
     
        ro.owner(this.settings.batch.owner)  // bcs make this consistent batch vs data
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(normalize.indicators)
            .pagination(this.settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod(method)
            .resultLimit(this.settings.api.resultLimit)
            .type(type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        // reset
        this.batchBody = [];
        this.iData.optionalData = {};
        this.iData.requiredData = {};
        this.iData.specificData = {};
        
        this.settings.callbacks.done = undefined;
        this.settings.callbacks.pagination = undefined;
        this.settings.callbacks.error = undefined;
    };
    
    c.groupEnd();
    return this;
}
Indicators.prototype = Object.create(ThreatConnect.prototype);

//
// Owners
//

function Owners(threatconnect) {
    c.group('Onwers');
    ThreatConnect.call(this, threatconnect);
    
    var ro = new RequestObject();
    this.settings = {
        api: {
            activityLog: false,             // false|true
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
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            this.settings.api.resultLimit = data;
        } else {
            console.warn('Invalid Result Count (' + data + ').');
        }
        return this;
    };
 
    //
    // Settings Callbacks
    //
    this.done = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.done = data;
        } else {
            c.error('Callback "done()" must be a function.');
        }
        return this;
    };
    
    this.error = function(data) {
        if (typeof data === 'function') {
            this.settings.callbacks.error = data;
        } else {
            c.error('Callback "error()" must be a function.');
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
        ro.done(this.settings.callbacks.done)
            .error(this.settings.callbacks.error)
            .helper(true)
            .normalization(normalize.owners)
            // .pagination(this.settings.callbacks.pagination)
            .requestUri('v2/owners')
            .requestMethod('GET');
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    this.getData = function(params) {
        return this.rData.requiredData;
    };
 
    c.groupEnd();
    return this;
}
Owners.prototype = Object.create(ThreatConnect.prototype);


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
    adversaries: function(ro, response) { 
        c.group('normalize.adversaries');
        var adversaries = [],
            status = response.status;
        
        if (response) {
            adversaries = response.data.adversary;
                
            if (Object.prototype.toString.call( adversaries ) != '[object Array]') {
                if (adversaries.owner) {
                    adversaries.ownerName = adversaries.owner.name;
                    delete adversaries.owner;
                }
                adversaries = [adversaries];
            }
            c.log('adversaries', adversaries);
            
            ro.response.data = $.merge(ro.response.data, adversaries);
            
            c.groupEnd();
        }
        return {status: status,
                data: adversaries};
    },
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
    documents: function(ro, response) { 
        c.group('normalize.documents');
        var documents = [],
            status = response.status;
            
        if (response) {
            documents = response.data.document;
            
            if (Object.prototype.toString.call( documents ) != '[object Array]') {
                if (documents.owner) {
                    documents.ownerName = documents.owner.name;
                    delete documents.owner;
                }
                documents = [documents];
            }
            c.log('document', document);
            
            ro.response.data = $.merge(ro.response.data, documents);
            
            c.groupEnd();
        }
        return {status: status,
                data: documents};
    },
    emails: function(ro, response) { 
        c.group('normalize.emails');
        var emails = [],
            status = response.status;
            
        if (response) {
            emails = response.data.email;
            
            if (Object.prototype.toString.call( emails ) != '[object Array]') {
                if (emails.owner) {
                    emails.ownerName = emails.owner.name;
                    delete emails.owner;
                }
                emails = [emails];
            }
            c.log('email', emails);
            
            ro.response.data = $.merge(ro.response.data, emails);
            
            c.groupEnd();
        }
        return {status: status,
                data: emails};
    },
    incidents: function(ro, response) { 
        c.group('normalize.incidents');
        var incidents = [],
            status = response.status;
                
        if (response) {
            incidents = response.data.incident;
            
            if (Object.prototype.toString.call( incidents ) != '[object Array]') {
                if (incidents.owner) {
                    incidents.ownerName = incidents.owner.name;
                    delete incidents.owner;
                }
                incidents = [incidents];
            }
            
            ro.response.data = $.merge(ro.response.data, incidents);
            
            c.groupEnd();
        }
        return {status: status,
                data: incidents};
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
    indicators2: function(ro, response) { 
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
            if ('type' in rvalue) {
                indicatorTypeData = indicatorHelper(rvalue.type.charAt(0).toLowerCase());
            }
            
            indicatorsData = {};
            $.each( indicatorTypeData.indicatorFields, function( ikey, ivalue ) {
                // change summary to proper field value
                // handle different types of hash
                
                // BCS FIX THIS FOR FILE HASHES
                if ('summary' in rvalue) {
                    indicatorsData[ivalue] = rvalue['summary'];
                } else {
                    indicatorsData[ivalue] = rvalue[ivalue];
                }
                // indicator: indicator.summary || indicator.ip || indicator.address
            });
            
            indicators.push({
                id: rvalue.id,
                indicators: indicatorsData,
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
    }
};

/*
*/