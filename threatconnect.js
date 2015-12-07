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

var c = console;

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
    OWNER: {
        'dataField': undefined,
        'type': 'Owner',
        'uri': 'owners',
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
    GT: '>',
    GE: '>=',
    LT: '<',
    LE: '<=',
    NE: '!=',
    OR: 'or'
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

function Filter(param) {

    var separator = '';
        filters = '';
        orParams = false;

    if (param == FILTER.OR) {
        orParams = true;
    }

    this.on = function(field, operator, value) {
        filters += separator + field + operator + value;
        separator = ',';
        c.log('ffffffffffffffffffffffffffffffffffilter', filters);

        return this;
    }

    this.get = function() {
        return {
            filters: filters,
            orParams: orParams
        }
    }

    return this;
}

function RequestObject() {
    c.groupCollapsed('RequestObject');
    var _this = this;

    this.ajax = {
        async: true,
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
        createActivityLog: 'false',
        resultLimit: 500,
        resultStart: 0
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
        pagination: false,
        previousCount: 0,
        previousCountMax: 10,
        remaining: 0,
        requestCount: 0,
        type: undefined,
        url: undefined,
    };
    
    //
    // authentication
    //
    this.setAuthentication = function(data) {
        this.authentication = data;
        return this;
    };

    //
    // payload
    //
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
        c.log('ddddddddddddddddddata', data.get());
        this.addPayload('filters', data.get().filters)
        this.addPayload('orParams', data.get().orParams)
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
        }
        return this;
    };
    
    this.resultStart = function(data) {
        this.addPayload('resultStart', data);
        return this;
    };
    
    //
    // headers
    //
    this.addHeader = function(key, val) {
        this.headers[key] = val;
        return this;
    };
    
    //
    // ajax settings
    //
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
        return this;
    };
    
    this.requestUri = function(uri) {
        this.ajax.requestUri = uri;
        return this;
    };
    
    //
    // functions
    //
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
    
    this.go = function() {
        this.apiRequest({action: 'go'});
    };
    
    this.hasNext = function() {
        c.log('hasNext', this.settings.requestCount);
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
                    c.warn('Pagination is not enabled.');
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
                    c.warn('Pagination is not enabled.');
                }
                _this.settings.previousCount++;
            }, 1000);
        }
        return this;
    };
    
    //
    // response
    //
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
        c.group('apiRequest');
        
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
        //     c.warn('ResultStart cannot be greater than resultCount.');
        //     return;
        // }
            
        // jQuery ajax does not allow query string paramaters and body to
        // be used at the same time.  The url has to rebuilt manually.
        // first api call will always be synchronous to get resultCount
        var defaults = {
            aysnc: false,
            url: this.ajax.requestMethod === 'GET' ? [this.authentication.apiUrl, this.ajax.requestUri].join('/') : this.settings.url.href,
            data: this.ajax.requestMethod === 'GET' ? this.payload : this.ajax.body,
            headers: this.headers,
            crossDomain: false,
            method: this.ajax.requestMethod,
            contentType: this.ajax.contentType,
        };
        c.log('defaults', defaults);
        c.log('this.url.href', this.settings.url.href);
        
        var apiPromise = $.ajax(defaults)
            .done(function (response) {
                c.log('response', response);
                // c.log('this', this);
                var currentCount = _this.settings.remaining,
                    upload_pattern = /upload/,
                    remaining = undefined;
                
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

                    var resultStart = getParameterFromUri('resultStart', this.url),
                        normalizedData = _this.settings.normalizer(_this.settings.type, response.data),
                        doneResponse = $.extend({
                            data: normalizedData,
                            remaining: remaining,
                            url: this.url
                        }, _this.response);
                        
                    if (_this.callbacks.done) {
                        if (_this.settings.helper) {
                            _this.callbacks.done(doneResponse);
                        } else {
                            _this.callbacks.done(response);
                        }
                    }
                    
                } else if (upload_pattern.test(_this._requestUri)) {
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else if (_this.response.requestMethod === 'DELETE') {
                    if (_this.callbacks.done) { _this.callbacks.done(_this.response); }
                } else {
                    c.log('ELSE');
                }
            })
            .fail(function (response) {
                _this.response.error = response.responseText;
                c.warn(response.responseText);
                
                if (_this.callbacks.error) {
                    _this.callbacks.error(_this.response);
                }
            });
            
        this.resultStart(this.payload.resultStart + this.payload.resultLimit);
        c.groupEnd();
        return apiPromise;
    };
    
    c.groupEnd();
    return this;
}

function ThreatConnect(params) {
    if (params.apiId && params.apiSec && params.apiUrl) {
        this.authentication = {
            'apiId': params.apiId,
            'apiSec': params.apiSec,
            'apiUrl': params.apiUrl
        };
    } else if (params.apiToken && params.apiUrl) {
        this.authentication = {
            'apiToken': params.apiToken,
            'apiUrl': params.apiUrl
        }
    } else {
        c.log('Required authentication parameters were not provided.')
        return false;
    }
    
    this.attributes = function() {
        return new Attributes(this.authentication);
    };
    
    this.groups = function() {
        return new Groups(this.authentication);
    };
    
    this.indicators = function() {
        return new Indicators(this.authentication);
    };
    
    this.owners = function() {
        return new Owners(this.authentication);
    };

    this.requestObject = function() {
        var ro = new RequestObject();
        ro.setAuthentication(this.authentication);
        return ro;
    };

    this.tags = function() {
        return new Tags(this.authentication);
    };
}

function Groups(authentication) {
    c.group('Group');
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = 'v2',
    this.settings.helper = true,
    this.settings.normalizer = normalize.groups,
    this.settings.type = TYPE.GROUP,
    this.rData = {
        id: undefined,
        associationType: undefined,
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

    this.id = function(data) {
        this.rData.id = data;
        return this;
    };

    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.type = data;
        }
        return this;
    };

    this.associationType = function(data) {
        if (data.type && data.uri) {
            this.rData.associationType = data;
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

        // validate required fields
        if (this.rData.requiredData.name) {

            // prepare body
            var specificBody = this.rData.specificData[this.settings.type.dataField];
            this.body($.extend(this.rData.requiredData, $.extend(this.rData.optionalData, specificBody)));
            this.requestMethod('POST');

            this.requestUri([
                this.ajax.requestUri,
                this.settings.type.uri,
                this.rData.id
            ].join('/'));

            if (this.rData.id) {
                this.requestMethod('PUT');
            }
            
            /* create job */ 
            //ro.owner(this.settings.api.owner)
            //    .activityLog(this.settings.api.activityLog)
            //    .body(body)
            //    .done(this.settings.callbacks.done)
            //    .error(this.settings.callbacks.error)
            //    .helper(true)
            //    .pagination(this.settings.callbacks.pagination)  // bcs - required for updates?
            //    .normalization(this.settings.api.normalizer)
            //    .requestUri(requestUri)
            //    .requestMethod(method)
            //    .type(this.settings.api.type);

            c.log('body', JSON.stringify(this.ajax.body, null, 4));
            this.apiRequest({action: 'commit'});
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
            var errorMessage = 'Commit Failure: group name is required.';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        } 
    };
    
    //
    // Delete Group
    //
    this.delete = function() {
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));

        //var ro = new RequestObject();
        //ro.owner(this.settings.api.owner)
        //    .activityLog(this.settings.api.activityLog)
        //    .done(this.settings.callbacks.done)
        //    .error(this.settings.callbacks.error)
        //    .helper(true)
        //    .id(this.settings.api.requestUriId)
        //    .requestUri(requestUri)
        //    .requestMethod('DELETE')
        //    .resultLimit(this.settings.api.resultLimit)
        //    .type(this.settings.api.type);
        //c.log('body', ro);
     
        this.apiRequest({action: 'delete'});
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function(callback) {
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));
        this.requestMethod('GET');
        c.log('this.ajax.requestUri', this.ajax.requestUri);
        this.settings.requestCount = this.payload.resultLimit;

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    //
    // Retrieve Associations
    //
    this.retrieveAssociations = function() {
        /* /v2/indicators/<indicator type>/<value>/groups */
        /* /v2/indicators/<indicator type>/<value>/groups/adversaries */

        /* /v2/groups/adversaries/81/indicators */
        /* /v2/groups/adversaries/81/indicators/hosts */
        /* /v2/groups/adversaries/81/groups */
        /* /v2/groups/adversaries/81/groups/incidents */

        this.normalization(normalize.find(this.rData.associationType.type));

        this.requestUri([
            'v2',
            this.settings.type.uri,
            this.rData.id,
            this.rData.associationType.uri,
        ].join('/'));
        c.log('this.ajax.requestUri', this.ajax.requestUri);
            
        this.apiRequest('associations');
    };
    
    //
    // Retrieve Attributes
    //
    this.retrieveAttributes = function() {
        /* /v2/groups/<group type>/<ID>/attributes */
        this.settings.normalizer = normalize.attributes;

        this.requestUri([
            'v2',
            this.settings.type.uri,
            this.rData.id,
            'attributes'
        ].join('/'));
        c.log('requestUri', this.ajax.requestUri);

        return this.apiRequest('attribute');
    };
    
    this.retrieveTags = function() {
        /* /v2/groups/<group type>/<ID>/tags */
        this.settings.normalizer = normalize.tags;

        this.requestUri([
            'v2',
            this.settings.type.uri,
            this.rData.id,
            'tags'
        ].join('/'));
        c.log('requestUri', this.ajax.requestUri);

        return this.apiRequest('tags');
    };
    
    c.groupEnd();
    return this;
}
Groups.prototype = Object.create(RequestObject.prototype);

function Indicators(authentication) {
    c.group('Indicators');
    RequestObject.call(this);
    
    this.authentication = authentication;
    this.batchBody = [],
    this.ajax.requestUri = 'v2',
    this.settings.helper = true,
    this.settings.normalizer = normalize.indicators,
    this.settings.type = TYPE.INDICATOR,
    // this.settings = {
    //     api: {
    //         // activityLog: false,             // false|true
    //         // limit: undefined,
    //         requestUriId: undefined,
    //         // resultLimit: 500,
    //         // owner: undefined,               // set twice due to batch
    //     }
    // },
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
    
    //
    // Settings Batch
    //
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
     
    //
    // Indicator Data - Required
    //
    this.indicator = function(data) {
        this.iData.requiredData.summary = data;
        return this;
    };
    
    this.type = function(data) {
        if (data.type && data.uri) {
            this.settings.type = data;
            this.iData.requiredData.type = data.type;
        }
        return this;
    };
    
    //
    // Indicator Data - Optional
    //
    
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

    // bcs ???
    //this.description = function(data) {
    //    this.iData.specificData.File.description = data;
    //    return this;
    //};
    
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
        if (this.payload.owner && this.batchBody.length != 0) {
            c.log('this.batch', JSON.stringify(this.batch, null, 4));
            
            this.body($.extend({owner: this.payload.owner}, this.batch));
            this.normalization(normalize.default);  // bcs rename
            this.requestUri('v2/batch');
            this.requestMethod('POST');
            this.done = this.callbacks.done;
            this.callbacks.done = undefined;
            
            /* create job */ 
            this.apiRequest({action: 'commit'})
                .done(function(jobResponse) {
                    c.log('jobResponse', jobResponse);
                    _this.batchId = jobResponse.data.batchId;
                    
                    _this.body(_this.batchBody);
                    _this.contentType('application/octet-stream');
                    _this.requestUri('v2/batch/' + jobResponse.data.batchId);
                        
                    /* post data */
                    _this.apiRequest({action: 'commit'})
                        .done(function(dataResponse) {
                            c.log('dataResponse', dataResponse);
                            
                            _this.body(_this.batchBody);
                            _this.contentType('application/octet-stream');
                            _this.requestUri('v2/batch/' + jobResponse.data.batchId);
                            _this.requestMethod('GET');
                            
                            var checkStatus = function() {
                                setTimeout(function() {
                                    console.log('status.frequency', _this.status.frequency);
                                    console.log('status.timeout', _this.status.timeout);
                                    
                                    /* get status */
                                    _this.apiRequest({action: 'status'})
                                        .done(function(statusResponse) {
                                            c.log('statusResponse', statusResponse);
                                                    
                                            if (statusResponse.data.batchStatus.status == 'Completed') {
                                                statusResponse.data.batchStatus.data = _this.batchBody;
                                                if (statusResponse.data.batchStatus.errorCount > 0) {
                                                    
                                                    _this.requestUri('v2/batch/' + jobResponse.data.batchId);
                                                    _this.requestMethod('GET');
                                                                
                                                    /* get errors */
                                                    _this.apiRequest({action: 'status'})
                                                        .done(function(errorResponse) {
                                                            c.log('errorResponse', errorResponse);
                                                                    
                                                            statusResponse.data.batchStatus.errors = JSON.parse(errorResponse);
                                                            _this.settings.callbacks.done(statusResponse.data.batchStatus);
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
    
    this.retrieve = function(callback) {
        
        this.ajax.requestUri += '/' + this.settings.type.uri;
        if (this.iData.requiredData.summary) {
            var indicator = this.iData.requiredData.summary;
            if (this.settings.type.type == 'URL') {
                indicator = encodeURIComponent(indicator);
            }
            this.ajax.requestUri += '/' + indicator;
        }
        this.settings.requestCount = this.payload.resultLimit;
        
        // return this.apiRequest('next');
        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
        
        // reset
        // this.batchBody = [];
        // this.iData.optionalData = {};
        // this.iData.requiredData = {};
        // this.iData.specificData = {};
        
        // this.settings.callbacks.done = undefined;
        // this.settings.callbacks.pagination = undefined;
        // this.settings.callbacks.error = undefined;
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
Indicators.prototype = Object.create(RequestObject.prototype);

function Owners(authentication) {
    c.group('Owners');
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = 'v2/owners',
    this.settings.helper = true,
    this.settings.normalizer = normalize.owners,
    this.settings.type = TYPE.OWNER,
    this.rData = {
        id: undefined,
        optionalData: {},
    };

    // Optional
    this.id = function(data) {
        if (intCheck('id', data)) {
            this.rData.id = data;
        }
        return this;
    };

    //
    // Retrieve Owners
    //
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
    
    c.groupEnd();
    return this;
}
Owners.prototype = Object.create(RequestObject.prototype);

function Tags(authentication) {
    c.group('Tags');
    RequestObject.call(this);
    // /v2/tags

    this.authentication = authentication;
    this.ajax.requestUri = 'v2',
    this.settings.helper = true,
    this.settings.normalizer = normalize.tags,
    this.settings.type = TYPE.TAG,
    this.rData = {
        id: undefined,
        indicator: undefined,
        optionalData: {},
    };

    // Optional
    //this.id = function(data) {
    //    if (intCheck('id', data)) {
    //        this.rData.id = data;
    //    }
    //    return this;
    //};
    //
    //this.indicator = function(data) {
    //    this.rData.indicator = data;
    //    return this;
    //};

    //
    // Retrieve Tag
    //
    this.retrieve = function(callback) {
        this.requestUri('v2/tags')
        if (this.rData.id) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.id);
        } else if (this.rData.indicator) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.id);
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };
    
    c.groupEnd();
    return this;
}
Tags.prototype = Object.create(RequestObject.prototype);

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

var normalize = {
    attributes: function(ro, response) { 
        c.group('normalize.attributes');
        var attributes = [];

        if (response) {
            attributes = response.attribute;
                
            if (Object.prototype.toString.call( attributes ) != '[object Array]') {
                attributes = [attributes];
            }
            c.log('attributes', attributes);
            
        }
        c.groupEnd();
        return attributes;
    },
    groups: function(type, response) {
        c.group('normalize.groups');
        var groups = [];

        c.log('type', type);
        c.log('response', response);

        if (response) {
            if (type.dataField in response) {
                groups = response[type.dataField];
            } else if ('group' in response) {
                groups = response.group
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
        c.groupEnd();
        return groups;
    },
    indicators: function(type, response) { 
        c.group('normalize.indicators', response);
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
        $.each(response, function(rkey, rvalue) {
            if (rvalue && rvalue.length == 0) {
                return;
            }

            if ('type' in rvalue) {
                indicatorType = indicatorHelper(rvalue.type.charAt(0).toLowerCase()).type;
            }

            indicatorsData = [];
            $.each(type.indicatorFields, function(ikey, ivalue) {
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
                type: indicatorType,
                threatAssessRating: rvalue.threatAssessRating,
                threatAssessConfidence: rvalue.threatAssessConfidence,
                webLink: rvalue.webLink,
            });
        });
        
        c.groupEnd();
        return indicators;
    },
    owners: function(type, response) {
        c.group('normalize.owners');
        var owners = [];

        if (response) {
            owners = response.owner;
            if (Object.prototype.toString.call( owners ) != '[object Array]') {
                owners = [owners];
            }
            c.log('owners', owners);
            c.groupEnd();
        }
        return owners;
    },
    tags: function(ro, response) { 
        c.group('normalize.tags');
        var tags = [];

        if (response) {
            tags = response.tag;
                
            if (Object.prototype.toString.call( tags ) != '[object Array]') {
                tags = [tags];
            }
            c.log('tags', tags);

        }
        c.groupEnd();
        return tags;
    },
    default: function(type, response) {
        c.group('normalize.default');
        // c.log('response', response);
        // ro.response.data = $.merge(ro.response.data, response);
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