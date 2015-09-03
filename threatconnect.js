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

function RequestObject(params) {
    var _this = this;

    if (!!(params.apiId && params.apiKey)) { return false; }
    
    this.apiId = params.apiId;
    this.apiSec = params.apiSec;
    this.apiUrl = (params.apiUrl ? params.apiUrl : 'https://api.threatconnect.com');

    this._getTimestamp = function() {
        var date = new Date().getTime();
        return Math.floor(date / 1000);
    };

    this.apiRequestHeader = function() {
        c.group('API Request Header')
        c.log('this', this);

        var timestamp = this._getTimestamp(),
            signature = [this.pathUrl, this.requestMethod, timestamp].join(':'),
            hmacSignature = CryptoJS.HmacSHA256(signature, this.apiSec),
            authorization = 'TC ' + this.apiId + ':' + CryptoJS.enc.Base64.stringify(hmacSignature);
    
        this.addHeader('Timestamp', timestamp),
        this.addHeader('Authorization', authorization);
        
        c.groupEnd();
    };

    this.payload = {};
    this.headers = {};
    this.body = null;
    this.requestMethod = 'GET';
    this.ownerAllowed = true;
    this.pathUrl = null;
    this.requestUri = null;
    this.resourcePagination = true;
    this.resultLimit = 200;
    this.contentType = 'application/json; charset=UTF-8';

    this.addPayload = function(key, val) {
        this.payload[key] = val;
        return this;
    };
    
    this.addHeader = function(key, val) {
        this.headers[key] = val;
        return this;
    };
    
    this.setBody = function(data) {
        this.body = JSON.stringify(data);
        return this;
    };
    
    this.setContentType = function(contentType) {
        this.contentType = contentType
        return this;
    };
    
    this.setActivityLog = function(bool) {
        this.addPayload('createActivityLog', bool.toString());
        return this;
    };
    
    this.setModifiedSince = function(data) {
        this.addPayload('modifiedSince', data);
        return this;
    };
    
    this.setOwner = function(data) {
        this.addPayload('owner', data);
        return this;
    };
    
    this.setPagination = function(pagination) {
        this.resourcePagination = pagination;
        return this;
    };
    
    this.setRequestUri = function(uri) {
        this.requestUri = uri;
        return this;
    };
    
    this.setOwnerAllowed = function(allowed) {
        this.ownerAllowed = allowed;
        return this;
    };
    
    this.setRequestMethod = function(method) {
        this.requestMethod = method;
        return this;
    };
    
    this.setResultLimit = function(limit) {
        this.resultLimit = limit;
        return this;
    };
    
    return this;
}


RequestObject.prototype.apiRequest = function(params) {
    c.group('API Request');
    c.log('this', this);

    var url = document.createElement('a');
    url.href = [
        [this.apiUrl, this.requestUri].join('/'), $.param(this.payload)
    ].join('?');

    c.log('url', url);

    this.pathUrl = url.pathname + url.search;
    this.apiRequestHeader();

    c.log('headers', this.headers);
    
    if (this.requestMethod === "GET") {
        data = this.payload;
        url = [this.apiUrl, this.requestUri].join('/');
    } else {
        data = this.body;
        url = [this.apiUrl, this.requestUri].join('/') + url.search;
    }

    defaults = {
        url: url,
        data: data,
        headers: this.headers,
        crossDomain: false,
        method: this.requestMethod,
        contentType: this.contentType,
        complete: function(data) {
            c.log('data', data)
        },
        success: function() {
            c.info('Success!')
        },
        error: function(data) {
            c.warn(data)
        }
    };
    c.log('defaults', defaults);

    var params = $.extend(defaults, params);
    c.log('params', params);
    $.ajax(params);

    c.groupEnd();
};