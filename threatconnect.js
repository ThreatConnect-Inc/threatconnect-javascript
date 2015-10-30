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

/*
 * Request Object
 */

function RequestObject(params) {
    c.group('RequestObject');

    // this.id = uuid.v4();
    this.async = true;
    this.body = null;
    this.contentType = 'application/json; charset=UTF-8';
    this.done = undefined;
    this.headers = {};
    this.limit = 500;
    this.normalizer = normalize.default;
    this.owner = null;
    // this.ownerAllowed = true;
    this.pagination = undefined;
    this.pathUrl = null;
    this.payload = {};
    this.remaining = 0;
    this.requestMethod = 'GET';
    this.requestUri = null;
    this.resultCount = 0;
    this.resultLimit = 200;
    this.resultList = [];
    this.resultStart = 0;
    this.type = undefined;

    this.addPayload = function(key, val) {
        this.payload[key] = val;
        return this;
    };
    
    this.addHeader = function(key, val) {
        this.headers[key] = val;
        return this;
    };
    
    this.setActivityLog = function(bool) {
        this.addPayload('createActivityLog', bool.toString());
        return this;
    };
    
    this.setAsync = function(data) {
        this.async = data;
        return this;
    };
    
    this.setBody = function(data) {
        this.body = JSON.stringify(data);
        return this;
    };
    
    this.setContentType = function(contentType) {
        this.contentType = contentType;
        return this;
    };
    
    this.setDone = function(data) {
        this.done = data;
        return this;
    };
    
    this.setModifiedSince = function(data) {
        this.addPayload('modifiedSince', data);
        return this;
    };
    
    this.setNormalization = function(method) {
        this.normalizer = method;
        return this;
    };
    
    this.setOwner = function(data) {
        this.addPayload('owner', data);
        this.owner = data;
        return this;
    };
    
    // this.setOwnerAllowed = function(allowed) {
    //     this.ownerAllowed = allowed;
    //     return this;
    // };
    
    this.setPagination = function(method) {
        this.pagination = method;
        return this;
    };
    
    this.setRemaining = function(data) {
        this.remaining = data;
        return this;
    };
    
    this.setRequestUri = function(uri) {
        this.requestUri = uri;
        return this;
    };
    
    this.setRequestMethod = function(method) {
        this.requestMethod = method;
        return this;
    };
    
    this.setResultCount = function(data) {
        this.resultCount = data;
        return this;
    };
    
    this.setResultLimit = function(limit) {
        this.addPayload('resultLimit', limit);
        this.resultLimit = limit;
        return this;
    };
    
    this.setResultStart = function(start) {
        this.addPayload('resultStart', start);
        this.resultStart = start;
        return this;
    };
    
    this.setType = function(data) {
        this.type = data;
        return this;
    };
    
    // this.getOwner = function() {
    //     return this.owner;
    // };
    
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
    this.apiToken = params.token;
    this.apiUrl = (params.apiUrl ? params.apiUrl : 'https://api.threatconnect.com');
    // secondary restriction if browser does not limit concurrent api requests
    this.concurrentCalls = (params.concurrentCalls ? params.concurrentCalls : 10);
    
    this.apiHmacRequestHeader = function (ro) {
        this._getTimestamp = function() {
            var date = new Date().getTime();
            return Math.floor(date / 1000);
        };

        var timestamp = this._getTimestamp(),
            signature = [ro.pathUrl, ro.requestMethod, timestamp].join(':'),
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
        url.href = [
            [host, pathname].join('/'), $.param(search)
        ].join('?');
        return url;
    };
    
    this.apiRequest = function(ro) {
        c.group('apiRequest');
        var _this = this,
            url = this.apiRequestUrl(this.apiUrl, ro.requestUri, ro.payload);
            
        if (this.apiToken) {
            this.apiTokenRequestHeader(ro);
        } else {
            // set pathname for hmac encryption
            ro.pathUrl = url.pathname + url.search;
            this.apiHmacRequestHeader(ro);
        }
            
        // jQuery ajax does not allow query string paramaters and body to
        // be used at the same time.  The url has to rebuilt manually.
        // first api call will always be synchronous to get resultCount
        var defaults = {
            aysnc: false,
            url: ro.requestMethod === 'GET' ? [this.apiUrl, ro.requestUri].join('/') : url.href,
            data: ro.requestMethod === 'GET' ? ro.payload : ro.body,
            headers: ro.headers,
            crossDomain: false,
            method: ro.requestMethod,
            contentType: ro.contentType,
            
        };
        // if (ro.requestUri == 'v2/groups/documents/4/upload') {
        //     c.log('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCS')
        //     var body = JSON.stringify({test: 'test'});
        //     var defaults1 = defaults;
        //     defaults1.body = body;
        //     defaults1.contentLength = body.length;
        //     defaults1.contentType = 'application/octet-stream';
        //     defaults1.beforeSend = function( xhr ) {
        //         xhr.overrideMimeType('application/octet-stream');
        //     };
        //     defaults1.headers = {
        //     "Content-Type":"application/octet-stream",
        //     "Content-Length": body.length,
        //     }
        //     // defaults.enctype = 'multipart/form-data';
        //     defaults1.processData = false;
        //     defaults1.contentType = false;
        //     defaults1.crossDomain = false;
        // }
        // c.log('ttttttttttttttt', defaults1);
        // c.log('url', url.href);
        // c.log('method', ro.requestMethod);
        // test = $.ajax(defaults1)
        // c.log('test!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', test)
        
        c.groupEnd();
        // make first api call
        return $.ajax(defaults).always(function (response) {
            c.log('response', response);
            c.log('method', ro.requestMethod);
            
            if (ro.pagination) {
                // callback for paginated results
                ro.pagination(ro.normalizer(ro, response));
            }
            
            // check for pagination support
            if (response.data) {
                if (response.data.resultCount) {
                    ro.setResultCount(response.data.resultCount)
                        .setResultStart(ro.resultStart + ro.resultLimit)
                        .setRemaining(ro.resultCount - ro.resultLimit);
                        
                    // c.log('ro.resultCount', ro.resultCount);
                    // c.log('ro.remaining', ro.remaining);
                    
                    _this.apiRequestPagination(ro);
                } else {
                    // callback for done
                    ro.done(ro.resultList);
                }
            } else if (ro.requestMethod === 'DELETE') {
                ro.done(response);
            }
        });
    };
    
    this.apiRequestPagination = function(ro) {
        var _this = this;
        c.group('apiRequestPagination');
        
        // stop processing if limit is reached
        if (ro.resultList.length >= ro.limit && ro.remaining <= 0) return;
        
        var ajaxRequests = [];
        for (var i=1;i<=this.concurrentCalls;i++) {
            c.log('remaining', ro.remaining);
            
            if (ro.remaining <= 0) {
                break;
            }
            
            var url = this.apiRequestUrl(this.apiUrl, ro.requestUri, ro.payload);
            
            if (this.apiToken) {
                this.apiTokenRequestHeader(ro);
            } else {
                // set pathname for hmac encryption
                ro.pathUrl = url.pathname + url.search;
                this.apiHmacRequestHeader(ro);
            }
         
            // jQuery ajax does not allow query string paramaters and body to
            // be used at the same time.  The url has to rebuilt manually.
            // first api call will always be synchronous to get resultCount
            var defaults = {
                aysnc: ro.async,
                url: ro.requestMethod === 'GET' ? [this.apiUrl, ro.requestUri].join('/') : url.href,
                data: ro.requestMethod === 'GET' ? ro.payload : ro.body,
                headers: ro.headers,
                crossDomain: false,
                method: ro.requestMethod,
                contentType: ro.contentType,
            };
                
            ajaxRequests.push($.ajax(defaults).always(function(response) {
                // callback for paginated results
                if (typeof ro.pagination === 'function') {
                    ro.pagination(ro.normalizer(ro, response));
                }
            }));
            ro.setResultStart(ro.resultStart + ro.resultLimit)
                .setRemaining(ro.remaining - ro.resultLimit);
        }
        // c.log('ajaxRequests', ajaxRequests);

        $.when.apply(jQuery, ajaxRequests).done(function () {
            // for (var i=0;i<arguments.length;i++) {
            //     console.log('Response for request #' + (i + 1) + ' is ' + arguments[i][0]);
            //     console.log(arguments[i][0]);
            // }
            if (ro.remaining > 0) {
                _this.apiRequestPagination(ro);
            } else {
                ro.done(ro.resultList);
            }
        });
        c.groupEnd();
    };
}

/*
 * Adversaries
 */

ThreatConnect.prototype.adversaries = function() {
    c.group('adversaries');
    
    var ro = new RequestObject(),
        settings = {
            api: {
                activityLog: false,             // false|true
                method: 'GET',
                requestUri: 'v2/groups/adversaries',
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
    this.id = function(data) {
        rData.deleteData.id = data;
        return this;
    };
    
    this.name = function(data) {
        rData.requiredData.name = data;
        return this;
    };

    //
    // Group Data - Optional
    //
    this.attributes = function(data) {
        if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
        if (typeof data === 'object' && data.length != 0) {
            rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.tags = function(data) {
        if (rData.optionalData.tags) {rData.optionalData.tags = []}
        var tag;
        if (typeof data === 'object' && data.length != 0) {
            for (tag in data) {
                rData.optionalData.tags.push({name: data[tag]});
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
        // c.log('commit');
        
        // validate required fields
        if (rData.requiredData.name && settings.api.owner) {
            
            /* create job */ 
            ro.setOwner(settings.api.owner)
                .setActivityLog(settings.api.activityLog)
                .setBody(rData.requiredData)
                .setDone(settings.callbacks.done)
                .setNormalization(normalize.default)
                .setRequestUri(settings.api.requestUri)
                .setRequestMethod('POST');
            // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
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
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(uri)
            .setRequestMethod('DELETE')
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setNormalization(normalize.adversaries)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(settings.api.requestUri)
            .setRequestMethod(settings.api.method)
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
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
 * Document
 */
ThreatConnect.prototype.documents = function() {
    c.group('incidents');
    
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
    this.fileName = function(data) {
        rData.requiredData.fileName = data;
        return this;
    };
    
    this.id = function(data) {
        rData.deleteData.id = data;
        return this;
    };
    
    this.name = function(data) {
        rData.requiredData.name = data;
        return this;
    };

    //
    // Group Data - Optional
    //
    
    this.fileSize = function(data) {
        rData.optionalData.fileSize = data;
        return this;
    };
    
    this.attributes = function(data) {
        if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
        if (typeof data === 'object' && data.length != 0) {
            rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.tags = function(data) {
        if (rData.optionalData.tags) {rData.optionalData.tags = []}
        var tag;
        if (typeof data === 'object' && data.length != 0) {
            for (tag in data) {
                rData.optionalData.tags.push({name: data[tag]});
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
        // c.log('commit');
        var body;
        
        // validate required fields
        if (rData.requiredData.name && settings.api.owner) {
            body = $.extend(rData.requiredData, rData.optionalData);
            
            // specificBody = rData.specificData[iData.requiredData.type],
            //     body = $.extend(body, specificBody);
            
            /* create job */ 
            ro.setOwner(settings.api.owner)
                .setActivityLog(settings.api.activityLog)
                .setBody(body)
                .setDone(settings.callbacks.done)
                .setNormalization(normalize.default)
                .setRequestUri(settings.api.requestUri)
                .setRequestMethod('POST');
            c.log('body', JSON.stringify(body, null, 4));
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
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(uri)
            .setRequestMethod('DELETE')
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setNormalization(normalize.documents)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(settings.api.requestUri)
            .setRequestMethod(settings.api.method)
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
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
            ro.setOwner(settings.api.owner)
                .setBody(rData.requiredData.body)
                .setContentType('application/octet-stream')
                .setDone(settings.callbacks.done)
                .setNormalization(normalize.default)
                .setRequestUri(uri)
                .setRequestMethod('POST');
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
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(uri)
            .setRequestMethod('DELETE')
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setNormalization(normalize.documents)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(settings.api.requestUri)
            .setRequestMethod(settings.api.method)
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
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
 * Incident
 */

ThreatConnect.prototype.incidents = function() {
    c.group('incidents');
    
    var ro = new RequestObject(),
        settings = {
            api: {
                activityLog: false,             // false|true
                method: 'GET',
                requestUri: 'v2/groups/incidents',
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
    this.id = function(data) {
        rData.deleteData.id = data;
        return this;
    };
    
    this.name = function(data) {
        rData.requiredData.name = data;
        return this;
    };

    //
    // Group Data - Optional
    //
    this.attributes = function(data) {
        if (!rData.optionalData.attributes) {rData.optionalData.attributes = []}
        if (typeof data === 'object' && data.length != 0) {
            rData.optionalData.attributes = $.merge(rData.optionalData.attributes, data);
        } else {
            c.error('Tags must be an array.');
        }
        return this;
    };
    
    this.tags = function(data) {
        if (rData.optionalData.tags) {rData.optionalData.tags = []}
        var tag;
        if (typeof data === 'object' && data.length != 0) {
            for (tag in data) {
                rData.optionalData.tags.push({name: data[tag]});
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
        // c.log('commit');
        
        // validate required fields
        if (rData.requiredData.name && settings.api.owner) {
            
            /* create job */ 
            ro.setOwner(settings.api.owner)
                .setActivityLog(settings.api.activityLog)
                .setBody(rData.requiredData)
                .setDone(settings.callbacks.done)
                .setNormalization(normalize.default)
                .setRequestUri(settings.api.requestUri)
                .setRequestMethod('POST');
            // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
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
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(uri)
            .setRequestMethod('DELETE')
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
        c.log('ro', ro);
     
        this.apiRequest(ro);
    };
 
    //
    // Retrieve Group
    //
    this.retrieve = function() {
        ro.setOwner(settings.api.owner)
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setNormalization(normalize.incidents)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(settings.api.requestUri)
            .setRequestMethod(settings.api.method)
            .setResultLimit(settings.api.resultLimit);
            // .setType(settings.data.type);
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
 * Indicators
 */
ThreatConnect.prototype.indicator = function() {
    c.group('add_indicator');
    
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
            ro.setActivityLog(settings.api.activityLog)
                .setBody(settings.batch)
                .setDone(settings.callbacks.done)
                .setNormalization(normalize.default)
                .setRequestUri('v2/batch')
                .setRequestMethod('POST');
            // c.log('settings.batch', JSON.stringify(settings.batch, null, 4));
            this.apiRequest(ro).always(function(prom) {
                ro.setActivityLog(settings.api.activityLog)
                    .setBody(batchBody)
                    .setContentType('application/octet-stream')
                    .setDone(settings.callbacks.done)
                    .setNormalization(normalize.default)
                    .setRequestUri('v2/batch/' + prom.data.batchId)
                    .setRequestMethod('POST');
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
     
        ro.setOwner(settings.batch.owner)  // bcs make this consistent batch vs data
            .setActivityLog(settings.api.activityLog)
            .setDone(settings.callbacks.done)
            .setNormalization(normalize.indicators)
            .setPagination(settings.callbacks.pagination)
            .setRequestUri(requestUri)
            .setRequestMethod(method)
            .setResultLimit(settings.api.resultLimit)
            .setType(type);
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
 * Normalizers
 */
var normalize = {
    adversaries: function(ro, response) { 
        c.group('normalize.adversaries');
        if (response) {
            var adversaries = response.data.adversary;
            c.log('adversaries', adversaries);
            
            ro.resultList = $.merge(ro.resultList, adversaries);
            
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
            
            ro.resultList = $.merge(ro.resultList, documents);
            
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
            
            ro.resultList = $.merge(ro.resultList, incidents);
            
            c.groupEnd();
            return incidents;
        }
        return undefined;
    },
    indicators: function(ro, response) { 
        c.group('normalize.indicators');
        var indicatorTypeData;
        
        if (ro.type) {
            // indicatorTypeData = indicatorType(ro.type.charAt(0));
            indicatorTypeData = ro.type,
            response = response.data[ro.type.dataField];
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
        ro.resultList = $.merge(ro.resultList, indicatorData);
        
        c.groupEnd();
        return indicatorData;
    },
    default: function(response) {
        c.group('normalize.default');
        c.groupEnd();
        return response;
    }
};

/*
*/