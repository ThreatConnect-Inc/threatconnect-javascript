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

function ThreatConnect(params) {
    if (!!(params.apiId && params.apiKey)) { return false; }
    
    this.apiId = params.apiId;
    this.apiSec = params.apiSec;
    this.apiUrl = (params.apiUrl ? params.apiUrl : 'https://api.threatconnect.com');
    this.concurrentCalls = 5  // bcs
    
    //
    // generate request headers
    //
    this.apiRequestHeader = function (ro) {
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
    
    
    //
    // make api request
    //
    // this.apiRequest = function(ro, cb) {
    //     var _this = this,
    //         data = null,
    //         url = document.createElement('a');
            
    //     // c.info('ro', ro);

    //     // ! This should be changed to build the url params and search properties
    //     url.href = [
    //         [this.apiUrl, ro.requestUri].join('/'), $.param(ro.payload)
    //     ].join('?');

    //     ro.pathUrl = url.pathname + url.search;
        
    //     this.apiRequestHeader(ro);
     
    //     // jQuery ajax does not allow query string paramaters and body to
    //     // be used at the same time.  The url has to rebuilt manually.
    //     if (ro.requestMethod === "GET") {
    //         data = ro.payload;
    //         url = [this.apiUrl, ro.requestUri].join('/');
    //     } else {
    //         data = ro.body;
    //         url = [this.apiUrl, ro.requestUri].join('/') + url.search;
    //     }

    //     var defaults = {
    //         aysnc: ro.async,
    //         url: url,
    //         data: data,
    //         headers: ro.headers,
    //         crossDomain: false,
    //         method: ro.requestMethod,
    //         contentType: ro.contentType,
    //         done: function(data) { return; },
    //         fail: function(data) { c.warn(data); },
    //         always: function(data) {
    //             c.log('data', data);
    //             cb(ro.normalizer(ro, data));
    //         }
    //     };

    //     if (ro.async) {
    //         $.when($.ajax(defaults)).always(function (a) {
    //             _this.calls.current--;
    //             if (a.data.resultCount) {
    //                 _this[ro.id] = a.data.resultCount;
    //             }
    //         });
    //     } else {
    //         return $.ajax(defaults);
    //     }
    // };
    
    this.genUrl = function(host, pathname, search) {
        // ! This should be changed to build the url params and search properties
        var url = document.createElement('a');
        url.href = [
            [host, pathname].join('/'), $.param(search)
        ].join('?');
        return url;
    };
    
    this.apiRequest = function(ro) {
        c.groupCollapsed('apiRequest2');
        c.log('apiRequest2');
        var _this = this,
            url = this.genUrl(this.apiUrl, ro.requestUri, ro.payload);
            
        // set pathname for hmac encryption
        ro.pathUrl = url.pathname + url.search;
        this.apiRequestHeader(ro);
     
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
        c.info('url', url.href);
        
        // make first api call
        $.ajax(defaults).always(function (response) {
            c.info('response', response);
            // callback for paginated results
            if (ro.pagination) {
                ro.pagination(ro.normalizer(ro, response));
            }
            
            // check for pagination support
            if (response.data.resultCount) {
                ro.setResultCount(response.data.resultCount)
                    .setResultStart(ro.resultStart + ro.resultLimit)
                    .setRemaining(ro.resultCount - ro.resultLimit);
                    
                c.log('ro.resultCount', ro.resultCount);
                c.log('ro.remaining', ro.remaining);
                
                _this.apiRequestPagination(ro);
            } else {
                // callback for always
                ro.always(ro.resultList);
            }
        });
        c.groupEnd();
    };
    
    this.apiRequestPagination = function(ro) {
        var _this = this;
        c.groupCollapsed('apiRequestPagination');
        
        // stop processing if limit is reached
        if (ro.resultList.length >= ro.limit && ro.remaining <= 0) return;
        
        var ajaxRequests = [];
        for (var i=0;i<=this.concurrentCalls;i++) {
            c.log('remaining', ro.remaining);
            
            if (ro.remaining <= 0) {
                break;
            }
            
            var url = this.genUrl(this.apiUrl, ro.requestUri, ro.payload);
            
            if (ro.authMethod === 'hmac') {
                // set pathname for hmac encryption
                ro.pathUrl = url.pathname + url.search;
                this.apiRequestHeader(ro);
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
                ro.always(ro.resultList);
            }
        });
        c.groupEnd();
    };
}

function RequestObject(params) {
    c.groupCollapsed('RequestObject');

    // this.id = uuid.v4();
    this.always = undefined;
    this.async = true;
    this.authMethod = 'hmac';  // hmac or token
    this.body = null;
    this.contentType = 'application/json; charset=UTF-8';
    this.headers = {};
    this.limit = 500;
    this.normalizer = normalize.default;
    this.owner = null;
    this.ownerAllowed = true;
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
    
    this.setAlways = function(data) {
        this.always = data;
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
    
    this.setOwnerAllowed = function(allowed) {
        this.ownerAllowed = allowed;
        return this;
    };
    
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
    
    this.getOwner = function() {
        return this.owner;
    };
    
    c.groupEnd();
    return this;
}

//
// getIndicator
//

ThreatConnect.prototype.Indicator = function() {
    // var _this = this;
    c.group('getIndicators');
    
    this.settings = {
        activityLog: false,

        // callbacks
        always: undefined,
        done: undefined,
        fail: undefined,
        pagination: undefined,
        indicator: undefined,
        method: 'GET',
        owner: undefined,
        ownerAllowed: true,
        requestUri: 'v2/indicators',
        resultLimit: 500,
        type: undefined,
    };
    var ro = new RequestObject();
    
    this.always = function(data) {
        this.settings.always = data;
        return this;
    };
    
    this.indicator = function(data) {
        this.settings.indicator = data;
        // this.setting.pagination.enabled = false;
        return this;
    };
    
    this.owner = function(data) {
        this.settings.owner = data;
        return this;
    };
    
    this.pagination = function(data) {
        this.settings.pagination = data;
        return this;
    };
    
    this.resultLimit = function(data) {
        if (0 > data <= 500) {
            this.settings.resultLimit = data;
        } else {
            console.warn('Invalid Result Count (' + data + ').');
        }
        return this;
    };

    this.type = function(data) {
        var indicatorTypes = ['addresses', 'emailAddresses', 'files', 'hosts', 'urls'];
        if ($.inArray(data, indicatorTypes) != -1) {
            this.settings.type = data;
        }
        return this;
    };
    
    this.get = function() {
        if (this.settings.type !== null) {
            this.settings.requestUri = [this.settings.requestUri, this.settings.type].join('/');
        
            if (this.settings.indicator !== null) {
                this.settings.requestUri = [this.settings.requestUri, this.settings.indicator].join('/');
            }
        }
        
        ro.setOwner(this.settings.owner)
            .setActivityLog(this.settings.activityLog)
            .setAlways(this.settings.always)
            .setType(this.settings.type)
            .setNormalization(normalize.indicators)
            .setOwnerAllowed(this.settings.ownerAllowed)
            .setPagination(this.settings.pagination)
            .setRequestUri(this.settings.requestUri)
            .setRequestMethod(this.settings.method)
            .setResultLimit(this.settings.resultLimit);
        c.log('ro', ro);
        
        this.apiRequest(ro);
        
    };
    
    c.groupEnd();
    return this;
};

var normalize = {
    indicators: function(ro, response) { 
        c.group('normalize.indicators');
        var indicatorTypeData = null;
        
        if (ro.type) {
            indicatorTypeData = indicatorType(ro.type.charAt(0));
            response = response.data[indicatorTypeData.dataField];
            if (!response.length) {
                response = [response];
            }
        } else {
            response = response.data.indicator;
        }
        
        var indicatorData = [];
        $.each( response, function( rkey, rvalue ) {
            c.log('rvalue', rvalue);
            if ('type' in rvalue) {
                indicatorTypeData = indicatorType(rvalue.type.charAt(0).toLowerCase());
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
        return response;
    }
};

function indicatorType(prefix) {
    var indicatorTypes = {
        'a': {
            'dataField': 'address',
            'indicatorFields': ['ip'],
            'type': 'Address',
        },
        'e': {
            'dataField': 'emailAddress',
            'indicatorFields': ['address'],
            'type': 'EmailAddress',
        },
        'f': {
            'dataField': 'file',
            'indicatorFields': ['md5', 'sha1', 'sha256'],
            'type': 'File',
        },
        'h': {
            'dataField': 'host',
            'indicatorFields': ['hostName'],
            'type': 'Host',
        },
        'u': {
            'dataField': 'url',
            'indicatorFields': ['text'],
            'type': 'URL',
        }
    };
    return indicatorTypes[prefix];
}