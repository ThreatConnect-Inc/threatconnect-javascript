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

//
// Request Object
//
function RequestObject(params) {
    c.group('RequestObject');

    // this.id = uuid.v4();
    this._async = true;
    this._body = null;
    this._contentType = 'application/json; charset=UTF-8';
    this._done = undefined;
    this._headers = {};
    this._limit = 50;
    this._normalizer = normalize.default;
    this._owner = null;
    this._pagination = undefined;
    this._pathUrl = null;
    this._payload = {};
    this._remaining = 0;
    this._requestMethod = 'GET';
    this._requestUri = null;
    this._resultCount = 0;
    this._resultLimit = 200;
    this._resultList = [];
    this._resultStart = 0;
    this._type = undefined;

    this.payload = function(key, val) {
        this._payload[key] = val;
        return this;
    };
    
    this.addHeader = function(key, val) {
        this._headers[key] = val;
        return this;
    };
    
    this.activityLog = function(bool) {
        this.payload('createActivityLog', bool.toString());
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
        this._body = JSON.stringify(data);
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
        this._requestMethod = method;
        return this;
    };
    
    this.resultCount = function(data) {
        this._resultCount = data;
        return this;
    };
    
    this.resultLimit = function(data) {
        this.payload('resultLimit', data);
        this._resultLimit = data;
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
    
function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"), results = regex.exec(location.search);
        return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
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
            signature = [ro._pathUrl, ro._requestMethod, timestamp].join(':'),
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
        // url.href = [
        //     [host, pathname].join('/'), $.param(search)
        // ].join('?');
        url.href =  host + '/' + pathname + '?' + $.param(search);
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
            url: ro._requestMethod === 'GET' ? [this.apiUrl, ro._requestUri].join('/') : url.href,
            data: ro._requestMethod === 'GET' ? ro._payload : ro._body,
            headers: ro._headers,
            crossDomain: false,
            method: ro._requestMethod,
            contentType: ro._contentType,
            
        };
        // c.log('url.href', url.href);
        
        c.groupEnd();
        // make first api call
        return $.ajax(defaults).always(function (response) {
            // c.log('response', response);
            // c.log('method', ro._requestMethod);
            
            if (ro._pagination) {
                // callback for paginated results
                ro._pagination(ro._normalizer(ro, response));
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
                    ro._done(ro._resultList);
                }
            } else if (ro._requestMethod === 'DELETE') {
                ro._done(response);
            }
        });
    };
    
    this.apiRequestPagination = function(ro) {
        var _this = this;
        c.group('apiRequestPagination');
        
        // stop processing if limit is reached
        if (ro._resultList.length >= ro._limit && ro._remaining <= 0) return;
        
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
                url: ro._requestMethod === 'GET' ? [this.apiUrl, ro._requestUri].join('/') : url.href,
                data: ro._requestMethod === 'GET' ? ro._payload : ro._body,
                headers: ro._headers,
                crossDomain: false,
                method: ro._requestMethod,
                contentType: ro._contentType,
            };
                
            ajaxRequests.push($.ajax(defaults).always(function(response) {
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
                ro._done(ro._resultList);
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
    
    this.incidents = function() {
        return new Incidents(this);
    };
    
    this.indicators = function() {
        return new Indicators(this);
    };
}

/*
 * Group
 */

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
            fail: undefined,
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
    // this.attributes = function(data) {
    //     if (!this.rData.optionalData.attributes) {this.rData.optionalData.attributes = []}
    //     if (typeof data === 'object' && data.length != 0) {
    //         this.rData.optionalData.attributes = $.merge(this.rData.optionalData.attributes, data);
    //     } else {
    //         c.error('Tags must be an array.');
    //     }
    //     return this;
    // };
    
    // this.tags = function(data) {
    //     if (this.rData.optionalData.tags) {this.rData.optionalData.tags = []}
    //     var tag;
    //     if (typeof data === 'object' && data.length != 0) {
    //         for (tag in data) {
    //             this.rData.optionalData.tags.push({name: data[tag]});
    //         }
    //     } else {
    //         c.error('Tags must be an array.');
    //     }
    //     return this;
    // };
    
    //
    // Group Process
    //
    this.commit = function() {
        // c.log('commit');
        
        // validate required fields
        if (this.rData.requiredData.name && this.settings.api.owner) {
            var body = $.extend(this.rData.requiredData, this.rData.optionalData);
            
            /* create job */ 
            ro.owner(this.settings.api.owner)
                .activityLog(this.settings.api.activityLog)
                .body(body)
                .done(this.settings.callbacks.done)
                .normalization(this.settings.api.cNormalizer)
                .requestUri(this.settings.api.requestUri)
                .requestMethod('POST');
            // c.log('this.settings.batch', JSON.stringify(this.settings.batch, null, 4));
            this.apiRequest(ro);
            
        } else {
            console.error('Commit Failure: group name and owner are required.');
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
            .pagination(this.settings.callbacks.pagination)
            .requestUri(uri)
            .requestMethod('DELETE')
            .resultLimit(this.settings.api.resultLimit);
            // .type(this.settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.owner(this.settings.api.owner)
            .activityLog(this.settings.api.activityLog)
            .done(this.settings.callbacks.done)
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
    this.settings.api.cNormalizer = normalize.default;
    this.settings.api.rNormalizer = normalize.adversaries;
}
Adversaries.prototype = Object.create(Groups.prototype);

//
// Documents
//
function Documents(threatconnect) {
    Groups.call(this, threatconnect);
    
    this.settings.api.requestUri = 'v2/groups/documents';
    this.settings.api.cNormalizer = normalize.default;
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
    this.settings.api.cNormalizer = normalize.default;
    this.settings.api.rNormalizer = normalize.incidents;
}
Incidents.prototype = Object.create(Groups.prototype);




// ThreatConnect.prototype.adversaries1 = function() {
//     c.group('adversaries');
    
//     var ro = new RequestObject(),
//         settings = {
//             api: {
//                 activityLog: false,             // false|true
//                 method: 'GET',
//                 requestUri: 'v2/groups/adversaries',
//                 resultLimit: 500
//             },
//             callbacks: {
//                 done: undefined,
//                 fail: undefined,
//                 pagination: undefined,
//             },
//         },
//         rData = {
//             optionalData: {},
//             deleteData: {},
//             requiredData: {},
//             specificData: {},
//         };
 
//     //
//     // Settings API
//     //
//     this.activityLog = function(data) {
//         // c.log('activityLog', data);
//         if (typeof data === 'boolean') {
//             settings.api.activityLog = data;
//         } else {
//             c.error('activityLog must be a boolean.');
//         }
//         return this;
//     };
    
//     this.resultLimit = function(data) {
//         if (0 > data <= 500) {
//             settings.api.resultLimit = data;
//         } else {
//             console.warn('Invalid Result Count (' + data + ').');
//         }
//         return this;
//     };
 
//     this.owner = function(data) {
//         settings.api.owner = data;
//         return this;
//     };
 
//     //
//     // Settings Callbacks
//     //
//     this.done = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.done = data;
//         } else {
//             c.error('Callback "done()" must be a function.');
//         }
//         return this;
//     };
    
//     this.error = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.error = data;
//         } else {
//             c.error('Callback "error()" must be a function.');
//         }
//         return this;
//     };
    
//     this.pagination = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.pagination = data;
//         } else {
//             c.error('Callback "pagination()" must be a function.');
//         }
//         return this;
//     };
 
//     //
//     // Group Data - Required
//     //
//     this.id = function(data) {
//         rData.deleteData.id = data;
//         return this;
//     };
    
//     this.name = function(data) {
//         rData.requiredData.name = data;
//         return this;
//     };

//     //
//     // Group Data - Optional
//     //
//     this.attributes = function(data) {
//         if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
//         if (typeof data === 'object' && data.length != 0) {
//             rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     this.tags = function(data) {
//         if (rData.optionalData.tags) {rData.optionalData.tags = []}
//         var tag;
//         if (typeof data === 'object' && data.length != 0) {
//             for (tag in data) {
//                 rData.optionalData.tags.push({name: data[tag]});
//             }
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     //
//     // Group Process
//     //
//     this.commit = function() {
//         // c.log('commit');
        
//         // validate required fields
//         if (rData.requiredData.name && settings.api.owner) {
            
//             /* create job */ 
//             ro.owner(settings.api.owner)
//                 .activityLog(settings.api.activityLog)
//                 .body(rData.requiredData)
//                 .done(settings.callbacks.done)
//                 .normalization(normalize.default)
//                 .requestUri(settings.api.requestUri)
//                 .requestMethod('POST');
//             // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
//             this.apiRequest(ro);
            
//         } else {
//             console.error('Commit Failure: group name and owner are required.');
//         } 
//     };
    
//     //
//     // Delete Group
//     //
//     this.delete = function() {
//         var uri = settings.api.requestUri + '/' + rData.deleteData.id;
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(uri)
//             .requestMethod('DELETE')
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
 
//     //
//     // Retrieve Group
//     //
//     this.retrieve = function() {
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .normalization(normalize.adversaries)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(settings.api.requestUri)
//             .requestMethod(settings.api.method)
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
    
//     this.getData = function(params) {
//         return rData.requiredData;
//     };
 
//     c.groupEnd();
//     return this;
// };

// ThreatConnect.prototype.documents1 = function() {
//     c.group('incidents');
    
//     var ro = new RequestObject(),
//         settings = {
//             api: {
//                 activityLog: false,             // false|true
//                 method: 'GET',
//                 requestUri: 'v2/groups/documents',
//                 resultLimit: 500
//             },
//             callbacks: {
//                 done: undefined,
//                 fail: undefined,
//                 pagination: undefined,
//             },
//         },
//         rData = {
//             optionalData: {},
//             deleteData: {},
//             requiredData: {},
//             specificData: {},
//         };
 
//     //
//     // Settings API
//     //
//     this.activityLog = function(data) {
//         // c.log('activityLog', data);
//         if (typeof data === 'boolean') {
//             settings.api.activityLog = data;
//         } else {
//             c.error('activityLog must be a boolean.');
//         }
//         return this;
//     };
    
//     this.resultLimit = function(data) {
//         if (0 > data <= 500) {
//             settings.api.resultLimit = data;
//         } else {
//             console.warn('Invalid Result Count (' + data + ').');
//         }
//         return this;
//     };
 
//     this.owner = function(data) {
//         settings.api.owner = data;
//         return this;
//     };
 
//     //
//     // Settings Callbacks
//     //
//     this.done = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.done = data;
//         } else {
//             c.error('Callback "done()" must be a function.');
//         }
//         return this;
//     };
    
//     this.error = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.error = data;
//         } else {
//             c.error('Callback "error()" must be a function.');
//         }
//         return this;
//     };
    
//     this.pagination = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.pagination = data;
//         } else {
//             c.error('Callback "pagination()" must be a function.');
//         }
//         return this;
//     };
 
//     //
//     // Group Data - Required
//     //
//     this.fileName = function(data) {
//         rData.requiredData.fileName = data;
//         return this;
//     };
    
//     this.id = function(data) {
//         rData.deleteData.id = data;
//         return this;
//     };
    
//     this.name = function(data) {
//         rData.requiredData.name = data;
//         return this;
//     };

//     //
//     // Group Data - Optional
//     //
    
//     this.fileSize = function(data) {
//         rData.optionalData.fileSize = data;
//         return this;
//     };
    
//     this.attributes = function(data) {
//         if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
//         if (typeof data === 'object' && data.length != 0) {
//             rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     this.tags = function(data) {
//         if (rData.optionalData.tags) {rData.optionalData.tags = []}
//         var tag;
//         if (typeof data === 'object' && data.length != 0) {
//             for (tag in data) {
//                 rData.optionalData.tags.push({name: data[tag]});
//             }
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     //
//     // Group Process
//     //
//     this.commit = function() {
//         // c.log('commit');
//         var body;
        
//         // validate required fields
//         if (rData.requiredData.name && settings.api.owner) {
//             body = $.extend(rData.requiredData, rData.optionalData);
            
//             // specificBody = rData.specificData[iData.requiredData.type],
//             //     body = $.extend(body, specificBody);
            
//             /* create job */ 
//             ro.owner(settings.api.owner)
//                 .activityLog(settings.api.activityLog)
//                 .body(body)
//                 .done(settings.callbacks.done)
//                 .normalization(normalize.default)
//                 .requestUri(settings.api.requestUri)
//                 .requestMethod('POST');
//             c.log('body', JSON.stringify(body, null, 4));
//             this.apiRequest(ro);
            
//         } else {
//             console.error('Commit Failure: group name and owner are required.');
//         } 
//     };
    
//     //
//     // Delete Group
//     //
//     this.delete = function() {
//         var uri = settings.api.requestUri + '/' + rData.deleteData.id;
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(uri)
//             .requestMethod('DELETE')
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
 
//     //
//     // Retrieve Group
//     //
//     this.retrieve = function() {
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .normalization(normalize.documents)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(settings.api.requestUri)
//             .requestMethod(settings.api.method)
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
    
//     this.getData = function(params) {
//         return rData.requiredData;
//     };
 
//     c.groupEnd();
//     return this;
// };


// /*
//  * Incident
//  */

// ThreatConnect.prototype.incidents = function() {
//     c.group('incidents');
    
//     var ro = new RequestObject(),
//         settings = {
//             api: {
//                 activityLog: false,             // false|true
//                 method: 'GET',
//                 requestUri: 'v2/groups/incidents',
//                 resultLimit: 500
//             },
//             callbacks: {
//                 done: undefined,
//                 fail: undefined,
//                 pagination: undefined,
//             },
//         },
//         rData = {
//             optionalData: {},
//             deleteData: {},
//             requiredData: {},
//             specificData: {},
//         };
 
//     //
//     // Settings API
//     //
//     this.activityLog = function(data) {
//         // c.log('activityLog', data);
//         if (typeof data === 'boolean') {
//             settings.api.activityLog = data;
//         } else {
//             c.error('activityLog must be a boolean.');
//         }
//         return this;
//     };
    
//     this.resultLimit = function(data) {
//         if (0 > data <= 500) {
//             settings.api.resultLimit = data;
//         } else {
//             console.warn('Invalid Result Count (' + data + ').');
//         }
//         return this;
//     };
 
//     this.owner = function(data) {
//         settings.api.owner = data;
//         return this;
//     };
 
//     //
//     // Settings Callbacks
//     //
//     this.done = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.done = data;
//         } else {
//             c.error('Callback "done()" must be a function.');
//         }
//         return this;
//     };
    
//     this.error = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.error = data;
//         } else {
//             c.error('Callback "error()" must be a function.');
//         }
//         return this;
//     };
    
//     this.pagination = function(data) {
//         if (typeof data === 'function') {
//             settings.callbacks.pagination = data;
//         } else {
//             c.error('Callback "pagination()" must be a function.');
//         }
//         return this;
//     };
 
//     //
//     // Group Data - Required
//     //
//     this.id = function(data) {
//         rData.deleteData.id = data;
//         return this;
//     };
    
//     this.name = function(data) {
//         rData.requiredData.name = data;
//         return this;
//     };

//     //
//     // Group Data - Optional
//     //
//     this.attributes = function(data) {
//         if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
//         if (typeof data === 'object' && data.length != 0) {
//             rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     this.tags = function(data) {
//         if (rData.optionalData.tags) {rData.optionalData.tags = []}
//         var tag;
//         if (typeof data === 'object' && data.length != 0) {
//             for (tag in data) {
//                 rData.optionalData.tags.push({name: data[tag]});
//             }
//         } else {
//             c.error('Tags must be an array.');
//         }
//         return this;
//     };
    
//     //
//     // Group Process
//     //
//     this.commit = function() {
//         // c.log('commit');
        
//         // validate required fields
//         if (rData.requiredData.name && settings.api.owner) {
            
//             /* create job */ 
//             ro.owner(settings.api.owner)
//                 .activityLog(settings.api.activityLog)
//                 .body(rData.requiredData)
//                 .done(settings.callbacks.done)
//                 .normalization(normalize.default)
//                 .requestUri(settings.api.requestUri)
//                 .requestMethod('POST');
//             // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
//             this.apiRequest(ro);
            
//         } else {
//             console.error('Commit Failure: group name and owner are required.');
//         } 
//     };
    
//     //
//     // Delete Group
//     //
//     this.delete = function() {
//         var uri = settings.api.requestUri + '/' + rData.deleteData.id;
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(uri)
//             .requestMethod('DELETE')
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
 
//     //
//     // Retrieve Group
//     //
//     this.retrieve = function() {
//         ro.owner(settings.api.owner)
//             .activityLog(settings.api.activityLog)
//             .done(settings.callbacks.done)
//             .normalization(normalize.incidents)
//             .pagination(settings.callbacks.pagination)
//             .requestUri(settings.api.requestUri)
//             .requestMethod(settings.api.method)
//             .resultLimit(settings.api.resultLimit);
//             // .type(settings.data.type);
//         c.log('ro', ro);
     
//         this.apiRequest(ro);
//     };
    
//     this.getData = function(params) {
//         return rData.requiredData;
//     };
 
//     c.groupEnd();
//     return this;
// };

//
// Indicators
//
    
// ThreatConnect.prototype.indicator = function() {
function Indicators(threatconnect) {
    c.group('add_indicator');
    Groups.call(this, threatconnect);
    
    var batchBody = [],
        settings = {
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
                fail: undefined,
                pagination: undefined,
            },
        },
        iData = {
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
            settings.api.activityLog = data;
        } else {
            c.error('activityLog must be a boolean.');
        }
        return this;
    };
    
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            settings.api.resultLimit = data;
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
            settings.batch.haltOnError = data;
        } else {
            c.error('Setting action must be of value (Create|Delete).');
        }
        return this;
    };
    
    this.attributeWriteType = function(data) {
        // c.log('attributeWriteType', data);
        if ($.inArray(data, ['Append', 'Replace']) != -1) {
            settings.batch.haltOnError = data;
        } else {
            c.error('Setting attributeWriteType must be of value (Append|Replace).');
        }
        return this;
    };
                
    this.haltOnError = function(data) {
        // c.log('haltOnError', data);
        if (typeof data === 'boolean') {
            settings.batch.haltOnError = data;
        } else {
            c.error('Setting haltOnError must be a boolean.');
        }
        return this;
    };
    
    this.owner = function(data) {
        // c.log('owner', data);
        if (typeof data === 'string') {
            settings.batch.owner = data;
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
    // Indicator Data - Required
    //
    this.indicator = function(data) {
        // c.log('indicator', data);
        iData.requiredData.summary = data;
        return this;
    };
    
    this.type = function(data) {
        // c.log('type', data.type);
        if (data.type && data.uri) {
            iData.requiredData.type = data.type;
        }
        return this;
    };
    
    //
    // Indicator Data - Optional
    //
    this.attribute = function(data) {
        if (!iData.optionalData.attributes) {iData.optionalData.attributes = []}
        if (typeof data === 'object' && data.length != 0) {
            iData.optionalData.attributes.push(data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.attributes = function(data) {
        if (!iData.optionalData.attributes) {iData.optionalData.attributes = []}
        if (typeof data === 'object' && data.length != 0) {
            iData.optionalData.attributes = $.merge(iData.optionalData.attributes, data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.confidence = function(data) {
        if (!isNaN(data)) {
            iData.optionalData.confidence = data;
        } else {
            c.error('Confidence must be an integer.', data);
        }
        return this;
    };
    
    this.descrition = function(data) {
        if (typeof data === 'string') {
            iData.optionalData.description = data;
        } else {
            c.error('Description must be a string.', data);
        }
        return this;
    };
    
    this.rating = function(data) {
        if (!isNaN(parseFloat(data))) {
            iData.optionalData.rating = data;
        } else {
            c.error('Rating must be a Float.', data);
        }
        return this;
    };
    
    this.tag = function(data) {
        if (!iData.optionalData.tags) {iData.optionalData.tags = []}
        if (typeof data === 'string') {
            iData.optionalData.tags.push({name: data});
        } else {
            c.error('Tags must be a string.');
        }
        return this;
    };
    
    this.tags = function(data) {
        if (!iData.optionalData.tags) {iData.optionalData.tags = []}
        var tag;
        if (typeof data === 'object' && data.length != 0) {
            for (tag in data) {
                iData.optionalData.tags.push({name: data[tag]});
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
        iData.specificData.File.description = data;
        return this;
    };
    
    //
    // Indicator Data - Host Specific
    //
    this.dnsActive = function(data) {
        if (typeof data === 'boolean') {
            iData.specificData.Host.dnsActive = data;
        }
        return this;
    };
    
    this.whoisActive = function(data) {
        if (typeof data === 'boolean') {
            iData.specificData.Host.whoisActive = data;
        }
        return this;
    };
    
    //
    // Indicator Data - Url Specific
    //
    this.source = function(data) {
        iData.specificData.URL.source = data;
        return this;
    };
    
    // Indicator Add (Batch)
    this.add = function() {
        var body = {},
            specificBody = {};
        
        if (iData.requiredData.summary && iData.requiredData.type) {
            // iData.optionalData[settings.type.postField] = settings.indicator;
            // iData.optionalData['summary'] = settings.indicator;
            // iData.optionalData['type'] = settings.type.type;
            body = $.extend(iData.requiredData, iData.optionalData);
            
            specificBody = iData.specificData[iData.requiredData.type],
                body = $.extend(body, specificBody);
                
            batchBody.push(body);
            
            iData.optionalData = {};
            iData.requiredData = {};
            iData.specificData = {};
        } else {
            console.error('Add Failure: indicator and type are required fields.');
        }
        return this;
    };
    
    // Indicator Commit to API
    this.commit = function() {
        var _this = this;
        // c.log('commit');
        
        // validate required fields
        if (settings.batch.owner && batchBody.length != 0) {
            
            /* create job */ 
            ro.activityLog(settings.api.activityLog)
                .body(settings.batch)
                .done(settings.callbacks.done)
                .normalization(normalize.default)
                .requestUri('v2/batch')
                .requestMethod('POST');
            // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
            this.apiRequest(ro).always(function(prom) {
                ro.activityLog(settings.api.activityLog)
                    .body(batchBody)
                    .contentType('application/octet-stream')
                    .done(settings.callbacks.done)
                    .normalization(normalize.default)
                    .requestUri('v2/batch/' + prom.data.batchId)
                    .requestMethod('POST');
                c.log('batchBody', JSON.stringify(batchBody, null, 4));
                c.log('ro', ro);
                _this.apiRequest(ro);
                
                // reset
                batchBody = [];
                iData.optionalData = {};
                iData.requiredData = {};
                iData.specificData = {};
            });
            
        } else {
            console.error('Commit Failure: batch owner and indicators are required.');
        } 
    };
    
    this.getData = function(params) {
        return batchBody;
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
     
        ro.owner(settings.batch.owner)  // bcs make this consistent batch vs data
            .activityLog(settings.api.activityLog)
            .done(settings.callbacks.done)
            .normalization(normalize.indicators)
            .pagination(settings.callbacks.pagination)
            .requestUri(requestUri)
            .requestMethod(method)
            .resultLimit(settings.api.resultLimit)
            .type(type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
        
        // reset
        batchBody = [];
        iData.optionalData = {};
        iData.requiredData = {};
        iData.specificData = {};
        
        settings.callbacks.done = undefined;
        settings.callbacks.pagination = undefined;
        settings.callbacks.error = undefined;
    };
    
    c.groupEnd();
    return this;
};

/*
 * Upload
 */
 
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
                fail: undefined,
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
    // Group Process
    //
    this.commit = function() {
        // c.log('commit');
        var body;
        
        // validate required fields
        if (rData.requiredData.body && settings.api.owner) {
            var uri = settings.api.requestUri + '/' + rData.requiredData.id + '/upload'
            
            /* create job */ 
            ro.owner(settings.api.owner)
                .body(rData.requiredData.body)
                .contentType('application/octet-stream')
                .done(settings.callbacks.done)
                .normalization(normalize.default)
                .requestUri(uri)
                .requestMethod('POST');
            c.log('body', rData.requiredData.body);
            this.apiRequest(ro);
            
        } else {
            console.error('Commit Failure: group name and owner are required.');
        } 
    };
    
    //
    // Delete Group
    //
    this.delete = function() {
        var uri = settings.api.requestUri + '/' + rData.deleteData.id;
        ro.owner(settings.api.owner)
            .activityLog(settings.api.activityLog)
            .done(settings.callbacks.done)
            .pagination(settings.callbacks.pagination)
            .requestUri(uri)
            .requestMethod('DELETE')
            .resultLimit(settings.api.resultLimit);
            // .type(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.owner(settings.api.owner)
            .activityLog(settings.api.activityLog)
            .done(settings.callbacks.done)
            .normalization(normalize.documents)
            .pagination(settings.callbacks.pagination)
            .requestUri(settings.api.requestUri)
            .requestMethod(settings.api.method)
            .resultLimit(settings.api.resultLimit);
            // .type(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
    
    this.getData = function(params) {
        return rData.requiredData;
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
        if (response) {
            var adversaries = response.data.adversary;
            c.log('adversaries', adversaries);
            
            ro._resultList = $.merge(ro._resultList, adversaries);
            
            c.groupEnd();
            return adversaries;
        }
        return undefined;
    },
    documents: function(ro, response) { 
        c.group('normalize.documents');
        if (response) {
            var documents = response.data.document;
            c.log('document', document);
            
            ro._resultList = $.merge(ro._resultList, documents);
            
            c.groupEnd();
            return documents;
        }
        return undefined;
    },
    incidents: function(ro, response) { 
        c.group('normalize.incidents');
        if (response) {
            var incidents = response.data.incident;
            c.log('incidents', incidents);
            
            ro._resultList = $.merge(ro._resultList, incidents);
            
            c.groupEnd();
            return incidents;
        }
        return undefined;
    },
    indicators: function(ro, response) { 
        c.group('normalize.indicators');
        var indicatorTypeData;
        
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
        
        var indicatorData = [];
        $.each( response, function( rkey, rvalue ) {
            // c.log('rvalue', rvalue);
            if ('type' in rvalue) {
                indicatorTypeData = indicatorHelper(rvalue.type.charAt(0).toLowerCase());
            }
            
            var indicators = {};
            $.each( indicatorTypeData.indicatorFields, function( ikey, ivalue ) {
                // change summary to proper field value
                // handle different types of hash
                
                // BCS FIX THIS FOR FILE HASHES
                if ('summary' in rvalue) {
                    indicators[ivalue] = rvalue['summary'];
                } else {
                    indicators[ivalue] = rvalue[ivalue];
                }
                // indicator: indicator.summary || indicator.ip || indicator.address
            });
            
            indicatorData.push({
                id: rvalue.id,
                indicators: indicators,
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
        ro._resultList = $.merge(ro._resultList, indicatorData);
        
        c.groupEnd();
        return indicatorData;
    },
    default: function(response) {
        c.group('normalize.default');
        c.groupEnd();
        return response;
    }
};
Indicators.prototype = Object.create(ThreatConnect.prototype);

/*
*/