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

/* global $, CryptoJS, TYPE */

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
    CAMPAIGN: {
        'dataField': 'campaign',
        'type': 'Campaign',
        'uri': 'groups/campaigns',
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
    EVENT: {
        'dataField': 'event',
        'type': 'Event',
        'uri': 'groups/events',
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
    INTRUSION_SET: {
        'dataField': 'intrusionSet',
        'type': 'IntrusionSet',
        'uri': 'groups/intrusionSets',
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
    REPORT: {
        'dataField': 'report',
        'type': 'Report',
        'uri': 'groups/reports',
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
    TASK: {
        'dataField': 'task',
        'type': 'Task',
        'uri': 'tasks',
    },
    URL: {
        'dataField': 'url',
        'postField': 'text',
        'indicatorFields': ['text'],
        'type': 'URL',
        'uri': 'indicators/urls',
    },
    VICTIM: {
        'dataField': 'victim',
        'type': 'Victim',
        'uri': 'victims',
    },
    VICTIM_ASSET: {
        'dataField': 'victimAsset',
        'type': 'VictimAsset',
        'uri': 'victimAssets',
    },
    VICTIM_ASSET_EMAIL_ADDRESSES: {
        'dataField': 'victimEmailAddress',
        'type': 'EmailAddress',
        'uri': 'victimAssets/emailAddresses',
    },
    VICTIM_ASSET_NETWORK_ACCOUNTS: {
        'dataField': 'victimNetworkAccount',
        'type': 'NetworkAccount',
        'uri': 'victimAssets/networkAccounts',
    },
    VICTIM_ASSET_PHONE_NUMBERS: {
        'dataField': 'victimPhone',
        'type': 'Phone',
        'uri': 'victimAssets/phoneNumbers',
    },
    VICTIM_ASSET_SOCAIL_NETWORKS: {
        'dataField': 'victimSocialNetwork',
        'type': 'SocialNetwork',
        'uri': 'victimAssets/socialNetworks',
    },
    VICTIM_ASSET_WEBSITES: {
        'dataField': 'victimWebSite',
        'type': 'WebSite',
        'uri': 'victimAssets/webSites',
    },
    WHOAMI: {
        'dataField': '',
        'type': 'whoami',
        'uri': 'whoami',
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

var groupHelper = function(type) {
    var gTypes = {
        'adversary': TYPE.ADVERSARY,
        'campaign': TYPE.CAMPAIGN,
        'document': TYPE.DOCUMENT,
        'email': TYPE.EMAIL,
        'event': TYPE.EVENT,
        'incident': TYPE.INCIDENT,
        'intrusion set': TYPE.INTRUSION_SET,
        'report': TYPE.REPORT,
        'signature': TYPE.SIGNATURE,
        'threat': TYPE.THREAT
    };
    return gTypes[type.toLowerCase()];
};

var indicatorHelper = function(type) {
    var iTypes = {
        'address': TYPE.ADDRESS,
        'emailaddress': TYPE.EMAIL_ADDRESS,
        'file': TYPE.FILE,
        'host': TYPE.HOST,
        'url': TYPE.URL
    };
    return iTypes[type.toLowerCase()];
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

    // TODO: should the line below be an assignment or conditional expression (e.g. === )? (3)
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

function RequestObject() {
    var _this = this;

    this.ajax = {
        async: true,
        baseUri: 'v2',
        body: undefined,
        contentType: 'application/json; charset=UTF-8',
        formData: undefined,
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
        resultLimit: 500,
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
    this.secureProxy = function(url) {
        // var secureProxyUrl = this.authentication.apiUrl.replace(/api$/, 'secureProxy?_targetUrl=');
        var server = window.location.protocol + "//" + window.location.host,
            secureProxyUrl = server + "/secureProxy?_targetUrl=";
        return secureProxyUrl + encodeURIComponent(url);
    };

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

    this.formData = function(data) {
        this.ajax.formData = data;
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
        if (this.settings.requestCount === 0) {
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
        /*
        console.log('timestamp', timestamp);
        console.log('signature', signature);
        console.log('hmacSignature', hmacSignature);
        console.log('authorization', authorization);
        */

        this.addHeader('Timestamp', timestamp);
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
        // first api call should always be synchronous in order to retrieve
        // resultCount, which the API only return when resultStart=0.

        var requestData;
        if (this.ajax.requestMethod == 'GET') {
            requestData = this.payload;
        } else {
            if (this.ajax.formData) {
                requestData = this.ajax.formData;
            } else {
                requestData = this.ajax.body;
            }
        }

        // var apiUrl = this.ajax.requestMethod === 'GET' ? [this.authentication.apiUrl, this.ajax.requestUri].join('/') : this.settings.url.href;
        var defaults = {
            aysnc: false,
            url: this.ajax.requestMethod === 'GET' ? [this.authentication.apiUrl, this.ajax.requestUri].join('/') : this.settings.url.href,
            // data: this.ajax.requestMethod === 'GET' ? this.payload : this.ajax.body,
            data: requestData,
            // data: this.ajax.requestMethod === 'GET' ? {} : this.ajax.body,
            headers: this.headers,
            crossDomain: false,
            method: this.ajax.requestMethod,
            contentType: this.ajax.formData ? false : this.ajax.contentType,
            processData: this.ajax.formData ? false: true,
        };

        var apiPromise = $.ajax(defaults)
            .done(function (response, textStatus, request) {
                // console.log('request.getAllResponseHeaders()', request.getAllResponseHeaders());
                var currentCount = _this.settings.remaining,
                    // upload_pattern = /upload/,
                    remaining,
                    responseContentType = request.getResponseHeader('Content-Type');

                _this.response.apiCalls++;
                // handle responses from custom metrics
                if (params === 'customMetric') {
                    if (response == undefined) {
                        response = {};
                        response.status = "Success";
                    }
                }
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
                            data: normalizedData,
                            remaining: remaining,
                            url: this.url
                        }, _this.response);
                    // console.info('doneResponse', doneResponse);

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

function ThreatConnect(params) {
    if (params.apiId && params.apiSec && params.apiUrl) {
        this.authentication = {
            'apiId': params.apiId,
            'apiSec': params.apiSec,
            'apiUrl': params.apiUrl,
            // 'proxyServer': undefined
        };
    } else if (params.apiToken && params.apiUrl) {
        this.authentication = {
            'apiToken': params.apiToken,
            'apiUrl': params.apiUrl,
            // 'proxyServer': params.proxyServer
        };
    } else {
        console.error('Required authentication parameters were not provided.');
        return false;
    }

    this.db = function() {
        return new Db(this.authentication);
    };

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

    this.secureProxy = function() {
        return new SecureProxy(this.authentication);
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

    this.tasks = function() {
        return new Tasks(this.authentication);
    };

    this.victims = function() {
        return new Victims(this.authentication);
    };

    this.whoami = function() {
        return new WhoAmI(this.authentication);
    };
}

// BCS
function Db(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.addHeader('DB-Method', 'GET');
    this.ajax.requestUri = this.ajax.baseUri + '/exchange/db';
    this.settings.helper = true;
    this.settings.normalizer = normalize.default;
    this.settings.type = undefined;
    this.command = undefined;
    this.domain = undefined;
    this.typeName = undefined;
    this.dbData = {};

    /* REQUIRED */

    this.command = function(data) {
        this.command = data;
        return this;
    };

    this.dbMethod = function(data) {
        if (valueCheck('dbMethod', data, ['DELETE', 'GET', 'POST', 'PUT'])) {
            this.addHeader('DB-Method', data);
        }
        return this;
    };

    this.domain = function(data) {
        if (valueCheck('domain', data, ['local', 'organization', 'system'])) {
            this.domain = data;
        }
        return this;
    };

    this.typeName = function(data) {
        this.typeName = data;
        return this;
    };

    /* OPTIONAL */

    this.data = function(data) {
        this.body(data);
        return this;
    };

    this.request = function() {
        /* POST - /v2/exchange/db/{domain}/{typeName}/{command} */

        this.requestUri([
            this.ajax.requestUri,
            this.domain,
            this.typeName,
            this.command
        ].join('/'));
        this.contentType('application/json');
        this.requestMethod('POST');

        return this.apiRequest('db');
    };

    return this;
}
Db.prototype = Object.create(RequestObject.prototype);


function Groups(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = 'v2';
    this.resultLimit(500);
    this.settings.helper = true;
    this.settings.normalizer = normalize.groups;
    this.settings.normalizerType = TYPE.GROUP;
    this.settings.type = TYPE.GROUP;
    this.rData = {
        id: undefined,
        associationType: undefined,
        associationId: undefined,
        optionalData: {},
        requiredData: {},
        specificData: {
            adversary: {},
            campaign: {},
            document: {},
            email: {},
            event: {},
            incident: {},
            intrusionSet: {},
            report: {},
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
        if (objectCheck('attributes', data) && data.length !== 0) {
            this.rData.optionalData.attribute.push(this.rData.optionalData.attribute, data);
        }
        return this;
    };

    this.tags = function(data) {
        if (this.rData.optionalData.tag) { this.rData.optionalData.tag = []; }
        var tag;
        if (objectCheck('tag', data) && data.length !== 0) {
            for (tag in data) {
                this.rData.optionalData.tag.push({name: data[tag]});
            }
        }
        return this;
    };

    /* TYPE SPECIFIC PARAMETERS */

    // campaign
    this.firstSeen = function(data) {
        this.rData.specificData.campaign.firstSeen = data;
        return this;
    };

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
        /* POST - /v2/groups/{type} */
        /* PUT - /v2/groups/{type}/{id} */
        var _this = this;

        // validate required fields
        if (this.rData.requiredData.name) {

            // prepare body
            var specificBody = this.rData.specificData[this.settings.type.dataField];
            this.body($.extend(this.rData.requiredData, $.extend(this.rData.optionalData, specificBody)));
            this.requestMethod('POST');

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri
            ].join('/'));

            if (this.rData.id) {
                this.requestUri([
                    this.ajax.baseUri,
                    this.rData.id
                ].join('/'));
                this.requestMethod('PUT');
            }

            return this.apiRequest({action: 'commit'})
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
        /* POST - /v2/groups/{type}/{id}/groups/{type}/{id} */
        /* POST - /v2/groups/{type}/{id}/indicators/{type}/{indicators} */
        this.normalization(normalize.find(association.type.type));
        var resourceId = association.id;
        if (association.type.type == 'URL' || association.type.type == 'EmailAddress') {
            resourceId = encodeURIComponent(association.id);
        }
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            resourceId
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('associations');
    };

    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* POST - /v2/groups/{type}/{id}/attributes */
        /* PUT - /v2/groups/{type}/{id}/attributes/{id} */

        if (attribute) {
            this.normalization(normalize.attributes);

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'attributes'
            ].join('/'));
            this.requestMethod('POST');
            this.body(attribute);

            // attribute update
            if (attribute.id) {
                this.requestUri([
                    this.ajax.requestUri,
                    attribute.id,
                ].join('/'));
                this.requestMethod('PUT');
            }
            return this.apiRequest('attribute');
        }
    };

    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* POST - /v2/groups/{type}/{id}/securityLabel/{name} */
        this.normalization(normalize.securityLabels);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('securityLabel');
    };

    // Commit Tag
    this.commitTag = function(tag) {
        /* POST - /v2/groups/{type}/{id}/tags/{name} */
        this.normalization(normalize.tags);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('tag');
    };

    // Delete
    this.delete = function() {
        /* DELETE - /v2/groups/{type}/{id} */

        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));

        this.requestMethod('DELETE');
        return this.apiRequest({action: 'delete'});
    };

    // Delete Associations
    this.deleteAssociation = function(association) {
        /* DELETE - /v2/groups/{type}/{id}/groups/{type}/{id} */
        /* DELETE - /v2/groups/{type}/{id}/indicators/{type}/{indicator} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('associations');
    };

    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* DELETE - /v2/groups/{type}/{id}/attributes/{id} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('attribute');
    };

    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* DELETE - /v2/groups/{type}/{id}/securityLabels/{name} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('securityLabel');
    };

    // Delete Tag
    this.deleteTag = function(tag) {
        /* DELETE - /v2/groups/{type}/{id}/tags/{name} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('tag');
    };

    // Retrieve
    this.retrieve = function(callback) {
        /* GET - /v2/groups */
        /* GET - /v2/groups/{type} */

        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));
        // bcs - should id be added separately ?
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
        /* GET - /v2/groups/{type}/{id}/groups */
        /* GET - /v2/groups/{type}/{id}/groups/{type} */
        /* GET - /v2/groups/{type}/{id}/indicators */
        /* GET - /v2/groups/{type}/{id}/indicators/{type} */
        /* GET - /v2/groups/{type}/{id}/victims */
        /* GET - /v2/groups/{type}/{id}/victims/{id} */
        /* GET - /v2/groups/{type}/{id}/victimAssets */
        /* GET - /v2/groups/{type}/{id}/victimAssets/{type} */

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
        /* GET - /v2/groups/{type}/{id}/attributes */
        this.settings.normalizer = normalize.attributes;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
        ].join('/'));
        if (attributeId !== undefined) {
            if (intCheck('attributeId', attributeId)) {
                this.requestUri([
                    this.ajax.requestUri,
                    attributeId
                ].join('/'));
            }
        }

        return this.apiRequest('attribute');
    };

    // Retrieve Security Labels
    this.retrieveSecurityLabel = function(label) {
        /* GET - /v2/groups/{type}/{id}/securityLabels */
        /* GET - /v2/groups/{type}/{id}/securityLabels/{name} */
        this.settings.normalizer = normalize.securityLabels;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels'
        ].join('/'));
        if (label) {
            this.requestUri([
                this.ajax.requestUri,
                label
            ].join('/'));
        }

        return this.apiRequest('securityLabel');
    };

    // Retrieve Tags
    this.retrieveTags = function(tagName) {
        /* GET - /v2/groups/{type}/{id}/tags */
        /* GET - /v2/groups/{type}/{id}/tags/{name} */
        this.settings.normalizer = normalize.tags;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags'
        ].join('/'));
        if (tagName) {
            this.requestUri([
                this.ajax.requestUri,
                tagName
            ].join('/'));
        }

        return this.apiRequest('tags');
    };

    // Retrieve Tags
    this.retrieveTasks = function() {
        /* GET - /v2/groups/{type}/{id}/tasks */
        this.settings.normalizer = normalize.tasks;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tasks'
        ].join('/'));

        return this.apiRequest('tasks');
    };

    // Download
    this.download = function(params) {
        /* GET - /v2/groups/documents/{id}/download */

        // this.contentType('application/octet-stream');
        this.requestMethod('GET');
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'download'
        ].join('/'));

        return this.apiRequest({action: 'get'});
    };

    // Upload
    this.upload = function(params) {
        /* POST - /v2/groups/documents/{id}/upload */
        /* PUT - /v2/groups/documents/{id}/upload */

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

        return this.apiRequest({action: 'commit'});
    };

    return this;
}
Groups.prototype = Object.create(RequestObject.prototype);

function Indicators(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.settings.helper = true;
    this.settings.normalizer = normalize.indicators;
    this.settings.type = TYPE.INDICATOR;
    this.settings.normalizerType = TYPE.INDICATOR;
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
        this.iData.optionalData.description = data;
        return this;
    };

    this.rating = function(data) {
        if (rangeCheck('rating', data, 0, 5)) {
            this.iData.optionalData.rating = data;
        }
        return this;
    };

    /* INDICATOR DATA SPECIFIC */

    // file
    this._getFileHash = function() {
        /* Return a file hash from an Object with file hashes. */
        var fileHash;

        for(var hash in this.iData.indicator) {
            fileHash = this.iData.indicator[hash];
            break;
        }

        return fileHash;
    };

    this.size = function(data) {
        /* Set the size of a file indicator. */
        if (intCheck('file size', data)) {
            this.iData.specificData.File.size = data;
        }
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

    /* INDICATOR UTILTIY FUNCTIONS */

    this._getSingleIndicatorValue = function(indicator) {
        /* Get a single (non-null) value from the indicator Object. */
        var indicatorValue;

        // iterate through the values of the indicator Object
        for(var indicatorField in indicator) {
            // get the value from the indicator Object
            indicatorValue = indicator[indicatorField];

            // if the indicator value is not undefined, stop iterating through the indicator Object
            if (indicatorValue != undefined) {
                break;
            }
        }

        // raise an error if the user passed in an empty Object
        if (indicatorValue === undefined) {
            var errorMessage = 'Request Failure: indicator is required (an empty Object was received).';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        } else {
            return indicatorValue;
        }
    };

    /* API ACTIONS */

    // Commit
    this.commit = function(callback) {
        /* POST - /v2/indicators/{type} */
        /* PUT - /v2/indicators/{type}/{indicator} */
        var _this = this;

        // validate required fields
        if (this.iData.indicator) {
            // validate the fields for the indicator
            if(this.iData.indicator.constructor == Object) {
                for(var indicatorField in this.iData.indicator) {
                    this.iData.requiredData[indicatorField] = this.iData.indicator[indicatorField];
                }
            }
            else {
                this.iData.requiredData[this.settings.type.postField] = this.iData.indicator;
            }

            // prepare body
            var specificBody = this.iData.specificData[this.settings.type.type];
            this.body($.extend(this.iData.requiredData, $.extend(this.iData.optionalData, specificBody)));

           this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
            ].join('/'));
            this.requestMethod('POST');

            this.apiRequest({action: 'commit'})
                .done(function(response) {
                    if (_this.settings.type.type == 'Address') {
                        _this.iData.indicator = response.data[_this.settings.type.dataField].ip;
                    }
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
        /* POST - /v2/indicators/{type}/{indicator}/groups/{type}/{id} */
        this.normalization(normalize.find(association.type.type));

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('associations');
    };

    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* POST - /v2/indicators/{type}/{indicator}/attributes */
        /* PUT - /v2/indicators/{type}/{indicator}/attributes/{id} */
        if (attribute) {
            this.normalization(normalize.attributes);

            // if the indicator is an Object, set the indicator to be one of the values in the Object
            if(this.iData.indicator.constructor == Object) {
                this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
            }

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
                'attributes'
            ].join('/'));
            this.requestMethod('POST');
            this.body(attribute);

            // attribute update
            if (attribute.id) {
                this.requestUri([
                    this.ajax.requestUri,
                    attribute.id,
                ].join('/'));
                this.requestMethod('PUT');
            }
            return this.apiRequest('attribute');
        }
    };

    // Commit False Positive
    this.commitFalsePositive = function(params) {
        /* POST - /v2/indicators/{type}/{indicator}/falsePositive */
        this.normalization(normalize.default);

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'falsePositive'
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('falsePositive');
    };

    // Commit File Action - Files Only
    this.commitFileAction = function(fileAction, association) {
        /* POST -  /v2/indicators/files/{fileHash}/actions/{fileAction}/indicators/{indicatorType}/{indicator} */
        this.normalization(normalize.find(association.type.type));

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.iData.indicator,
            'actions',
            fileAction,
            association.type.uri,
            association.type.type == 'URL' || association.type.type == 'EmailAddress' ? encodeURIComponent(association.id) : association.id,
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('actions');
    };

    // Commit File Occurrence - File Indicators only
    this.commitFileOccurrence = function(fileOccurrence) {
        /* POST - /v2/indicators/files/{fileHash}/fileOccurrences */
        /* PUT - /v2/indicators/files/{fileHash}/fileOccurrences/{id} */
        // check to make sure the current indicator type is a file
        if (this.settings.type.type == 'File') {
            if (fileOccurrence) {
                this.normalization(normalize.fileOccurrences);

                // if the indicator is an Object, set the indicator to be one of the values in the Object
                if(this.iData.indicator.constructor == Object) {
                    this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
                }

                this.requestUri([
                    this.ajax.baseUri,
                    this.settings.type.uri,
                    this.iData.indicator,
                    'fileOccurrences'
                ].join('/'));
                this.requestMethod('POST');
                this.body(fileOccurrence);

                // update an existing fileOccurrence
                if (fileOccurrence.id) {
                    this.requestUri([
                        this.ajax.requestUri,
                        attribute.id,
                    ].join('/'));
                    this.requestMethod('PUT');
                }
                return this.apiRequest('fileOccurrence');
            }
        }
    };

    // Commit Observation
    this.commitObservation = function(params) {
        /* POST - /v2/indicators/{type}/{indicator}/observation */

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'observations'
        ].join('/'));
        this.requestMethod('POST');
        this.body({
            count: params.count,
            dateObserved: params.dateObserved
        });

        return this.apiRequest('attribute');
    };

    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* POST - /v2/indicators/{type}/{indicator}/securityLabels/{name} */
        this.normalization(normalize.securityLabels);

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('securityLabel');
    };

    // Commit Tag
    this.commitTag = function(tag) {
        /* POST - /v2/indicators/{type}/{indicator}/tags/{name} */
        this.normalization(normalize.tags);

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('tag');
    };

    // Delete
    this.delete = function() {
        /* DELETE - /v2/indicators/{type}/{indicator} */
        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
        ].join('/'));

        this.requestMethod('DELETE');
        return this.apiRequest({action: 'delete'});
    };

    // Delete Associations
    this.deleteAssociation = function(association) {
        /* DELETE - /v2/indicators/{type}/{indicator}/groups/{type}/{id} */
        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('associations');
    };

    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* DELETE - /v2/indicators/{type}/{indicator}/attributes/{id} */
        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('attribute');
    };

    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* DELETE - /v2/indicators/{type}/{indicator}/securityLabels/{name} */
        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('securityLabel');
    };

    // Delete Tag
    this.deleteTag = function(tag) {
        /* DELETE - /v2/indicators/{type}/{indicator}/tags/{name} */
        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('tag');
    };

    // retrieve
    this.retrieve = function(callback) {
        /* GET - /v2/indicators/ */
        /* GET - /v2/indicators/{type} */
        /* GET - /v2/indicators/{type}/{indicator} */

        // if there is an indicator and if said indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator && this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        // this.ajax.requestUri += '/' + this.settings.type.uri;
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri
        ].join('/'));
        if (this.iData.indicator) {
            this.requestUri([
                this.ajax.requestUri,
                this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            ].join('/'));
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
        /* GET - /v2/indicators/{type}/{indicator}/groups */
        /* GET - /v2/indicators/{type}/{indicator}/groups/{type} */
        /* GET - /v2/indicators/{type}/{indicator}/groups/{type}/{id} */
        /* GET - /v2/indicators/{type}/{indicator}/victims */
        /* GET - /v2/indicators/{type}/{indicator}/victims/{id} */
        /* GET - /v2/indicators/{type}/{indicator}/victimAssets */
        /* GET - /v2/indicators/{type}/{indicator}/victimAssets/{type} */
        /* GET - /v2/indicators/{type}/{indicator}/indicators */
        /* GET - /v2/indicators/{type}/{indicator}/indicators/{type} */
        /* GET - /v2/indicators/{type}/{indicator}/indicators/{type}/{indicator} */

        this.normalization(normalize.find(association.type.type));
        this.normalizationType(association.type);

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
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
        /* GET - /v2/indicators/{type}/{indicator}/attributes */
        /* GET - /v2/indicators/{type}/{indicator}/attributes/{id} */

        this.settings.normalizer = normalize.attributes;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'attributes',
        ].join('/'));
        if (attributeId !== undefined) {
            if (intCheck('attributeId', attributeId)) {
                this.requestUri([
                    this.ajax.requestUri,
                    attributeId
                ].join('/'));
            }
        }

        return this.apiRequest('attribute');
    };

    // Retrieve Observations
    this.retrieveObservations = function(attributeId) {
        /* GET - /v2/indicators/{type}/{indicator}/observations */

        this.settings.normalizer = normalize.observations;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'observations',
        ].join('/'));

        return this.apiRequest('observations');
    };

    // Retrieve ObservationCount
    this.retrieveObservationCount = function(attributeId) {
        /* GET - /v2/indicators/{type}/{indicator}/observationCount */

        this.settings.normalizer = normalize.observationCount;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'observationCount',
        ].join('/'));

        return this.apiRequest('observationCount');
    };

    // Retrieve Owners
    this.retrieveOwners = function(label) {
        /* GET - /v2/indicators/{type}/{indicator}/owners */

        this.settings.normalizer = normalize.owners;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'owners'
        ].join('/'));
        if (label) {
            this.requestUri([
                this.ajax.requestUri,
                label
            ].join('/'));
        }

        return this.apiRequest('owners');
    };

    // Retrieve Security Labels
    this.retrieveSecurityLabel = function(label) {
        /* GET - /v2/indicators/{type}/{indicator}/securityLabels */
        /* GET - /v2/indicators/{type}/{indicator}/securityLabels/{name} */

        this.settings.normalizer = normalize.securityLabels;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'securityLabels'
        ].join('/'));
        if (label) {
            this.requestUri([
                this.ajax.requestUri,
                label
            ].join('/'));
        }

        return this.apiRequest('securityLabel');
    };

    // Retrieve Tags
    this.retrieveTags = function(tagName) {
        /* GET - /v2/indicators/{type}/{indicator}/tags */
        /* GET - /v2/indicators/{type}/{indicator}/tags/{name} */

        this.settings.normalizer = normalize.tags;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'tags'
        ].join('/'));
        if (tagName) {
            this.requestUri([
                this.ajax.requestUri,
                tagName
            ].join('/'));
        }

        return this.apiRequest('tags');
    };

    // Retrieve Tasks
    this.retrieveTasks = function() {
        /* GET - /v2/indicators/{type}/{indicator}/tasks */

        this.settings.normalizer = normalize.tasks;

        // if the indicator is an Object, set the indicator to be one of the values in the Object
        if(this.iData.indicator.constructor == Object) {
            this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
        }

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
            'tasks'
        ].join('/'));

        return this.apiRequest('tasks');
    };

    // dnsResolutions
    this.dnsResolutions = function() {
        /* GET - /v2/indicators/hosts/{indicator}/dnsResolutions */
        /* GET - /v2/indicators/addresses/{indicator}/dnsResolutions */
        if (this.settings.type == TYPE.HOST || this.settings.type == TYPE.ADDRESS) {
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
        /* GET - /v2/indicators/files/{indicator}/fileOccurrences */
        if (this.settings.type == TYPE.FILE) {
            this.settings.normalizer = normalize.fileOccurrences;

            // if the indicator is an Object, set the indicator to be one of the values in the Object
            if(this.iData.indicator.constructor == Object) {
                this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
            }

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

    // update
    this.update = function(callback) {
        /* PUT - /v2/indicators/{type}/{indicator} */

        // validate required fields
        if (this.iData.indicator) {
            // if the indicator is an Object, set the indicator to be one of the values in the Object
            if(this.iData.indicator.constructor == Object) {
                this.iData.indicator = this._getSingleIndicatorValue(this.iData.indicator);
            }

            // prepare body
            var specificBody = this.iData.specificData[this.settings.type.type];
            this.body($.extend(this.iData.requiredData, $.extend(this.iData.optionalData, specificBody)));

            // TODO: Is the check below necessary? (3)
            if (this.iData.indicator) {
                this.requestUri([
                    this.ajax.baseUri,
                    this.settings.type.uri,
                    this.settings.type.type == 'URL' || this.settings.type.type == 'EmailAddress' ? encodeURIComponent(this.iData.indicator) : this.iData.indicator,
                ].join('/'));
                this.requestMethod('PUT');
            }

            this.apiRequest({action: 'update'})
                .done(function(response) {
                    if (callback) callback();
                });

        } else {
            var errorMessage = 'Update Failure: indicator is required.';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        }
    };


    return this;
}
Indicators.prototype = Object.create(RequestObject.prototype);

function IndicatorsBatch(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.batchBody = [];
    this.ajax.requestUri = 'v2';
    this.settings.helper = true;
    this.settings.normalizer = normalize.indicators;
    this.settings.type = TYPE.INDICATOR;
    this.settings.normalizerType = TYPE.INDICATOR;
    this.batch = {
        action: 'Create',               // Create|Delete
        attributeWriteType: 'Append',   // Append|Replace
        haltOnError: false,             // false|true
        owner: undefined,
    };
    this.status = {
        frequency: 1000,                // default: 1 second start
        timeout: 300000,                // default: 5 minutes
        multiplier: 2,                  // default: 2
        maxFrequency: 30000,            // deafult: 30 seconds
    };
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
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length !== 0) {
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
        if (rangeCheck('rating', data, 0, 5)) {
            this.iData.optionalData.rating = data;
        } else {
            console.error('Invalid rating value.', data);
        }
        return this;
    };

    this.tags = function(data) {
        var tag;
        // if (typeof data === 'object' && data.length != 0) {
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length !== 0) {
            if (!this.iData.optionalData.tag) { this.iData.optionalData.tag = []; }
            for (tag in data) {
                this.iData.optionalData.tag.push({name: data[tag]});
            }
        } else {
            console.error('Tags must be an array.');
        }
        return this;
    };

    this.associatedGroup = function(data) {
        var associatedGroup;
        if (Object.prototype.toString.call( data ) === '[object Array]' && data.length !== 0) {
            if (!this.iData.optionalData.associatedGroup) { this.iData.optionalData.associatedGroup = []; }
            for (associatedGroup in data) {
                this.iData.optionalData.associatedGroup.push(data[associatedGroup]);
            }
        } else {
            console.error('associatedGroup must be an array.');
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
            body = $.extend(this.iData.requiredData, this.iData.optionalData);

            // TODO: Not sure what is going on on the lines below (1)
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
    this.commit = function(callback) {
        var _this = this,
            message;

        // validate required fields
        if (this.payload.owner && this.batchBody.length !== 0) {

            this.body($.extend({owner: this.payload.owner}, this.batch));
            this.normalization(normalize.default);  // bcs rename
            this.requestUri(this.ajax.baseUri + '/batch');
            this.requestMethod('POST');
            this.done = this.callbacks.done;
            this.callbacks.done = undefined;

            /* POST (create job) - /v2/batch */
            this.apiRequest({action: 'commit'})
                .done(function(jobResponse) {
                    _this.batchId = jobResponse.data.batchId;

                    _this.body(_this.batchBody);
                    _this.contentType('application/octet-stream');
                    _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId);

                    /* POST (data) - /v2/batch/{id} */
                    _this.apiRequest({action: 'commit'})
                        .done(function(dataResponse) {

                            _this.body(_this.batchBody);
                            _this.contentType('application/octet-stream');
                            _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId);
                            _this.requestMethod('GET');

                            var checkStatus = function() {
                                setTimeout(function() {
                                    /*
                                    console.log('status.frequency', _this.status.frequency);
                                    console.log('status.timeout', _this.status.timeout);
                                    */

                                    /* GET (status) - /v2/batch/{id} */
                                    _this.apiRequest({action: 'status'})
                                        .done(function(statusResponse) {

                                            if (statusResponse.data.batchStatus.status == 'Completed') {
                                                statusResponse.data.batchStatus.data = _this.batchBody;
                                                if (statusResponse.data.batchStatus.errorCount > 0) {

                                                    _this.requestUri(_this.ajax.baseUri + '/batch/' + jobResponse.data.batchId + '/errors/');
                                                    _this.requestMethod('GET');

                                                    /* GET (errors) - /v2/batch/{id}/errors */
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
                                                if (callback) callback();
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
                    _this.callbacks.error(message);
                });
        } else {
            console.error('Commit Failure: batch owner and indicators are required.');
        }

        return this;
    };

    // retrieve
    this.retrieve = function(format) {
        /* GET - /v2/indicators/bulk/csv */
        /* GET - /v2/indicators/bulk/json */

        this.requestUri(this.ajax.baseUri + '/indicators/bulk/' + format);
        this.normalization(normalize.indicatorsBatch);
        return this.apiRequest('next');
    };

    // retrieve batch status
    this.retrieveBatchStatus = function() {
        /* GET - /v2/indicators/bulk */

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
    this.ajax.requestUri = this.ajax.baseUri + '/owners';
    this.settings.helper = true;
    this.settings.normalizer = normalize.owners;
    this.settings.type = TYPE.OWNER;
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
        /* GET - /v2/owners */
        /* GET - /v2/owners/{id} */

        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id
            ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };

    // Retrieve Owners Members
    this.retrieveMembers = function(callback) {
        /* GET - /v2/owners/mine/members */

        this.settings.normalizer = normalize.default;
        this.requestUri([
            this.ajax.requestUri,
            'mine/members'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('members');
    };

    // Retrieve Owners Metrics
    this.retrieveMetrics = function() {
        /* GET - /v2/owners/metrics */

        if (this.rData.id) {
            this.requestUri(this.ajax.requestUri + '/' + this.rData.id);
        }
        this.requestUri([
            this.ajax.requestUri,
            'metrics'
        ].join('/'));
        this.requestMethod('GET');
        this.settings.normalizer = normalize.default;

        return this.apiRequest('owner');
    };

    // Retrieve Owners Mine
    this.retrieveMine = function(callback) {
        /* GET - /v2/owners/mine */

        this.settings.normalizer = normalize.default;
        this.requestUri([
            this.ajax.requestUri,
            'mine'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('mine');
    };

    return this;
}
Owners.prototype = Object.create(RequestObject.prototype);

function SecurityLabels(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/securityLabels';
    this.settings.helper = true;
    this.settings.normalizer = normalize.securityLabels;
    this.settings.type = TYPE.SECURITY_LABELS;
    this.rData = {
        name: undefined,
    };

    /* OPTIONAL */
    this.name = function(data) {
        this.rData.name = data;
        return this;
    };

    /* All Security Labels commits are accessible via the individual resource commits. */
    /* All Security Labels deletes are accessible via the individual resource deletes. */

    //
    // Retrieve Security Labels
    //
    this.retrieve = function(callback) {
        /* GET - /v2/securityLabels */
        /* GET - /v2/securityLabels/{name} */
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

    this.retrieveTasks = function() {
        /* GET - /v2/securityLabels/{name}/tasks */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'tasks'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    this.retrieveVictims = function() {
        /* GET - /v2/securityLabels/{name}/victims */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'victims'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    this.retrieveVictimAssets = function() {
        /* GET - /v2/securityLabels/{name}/victimAssets */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'victimAssets'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    return this;
}
SecurityLabels.prototype = Object.create(RequestObject.prototype);

function Tasks(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/tasks';
    this.settings.helper = true;
    this.settings.normalizer = normalize.tasks;
    this.settings.type = TYPE.TASK;
    this.rData = {
        id: undefined,
        optionalData: {},
        requiredData: {}
    };

    /* SETTINGS API */
    this.id = function(data) {
        this.rData.id = data;
        return this;
    };

    /* TASK COMMIT REQUIRED */
    this.name = function(data) {
        this.rData.requiredData.name = data;
        return this;
    };

    /* TASK COMMIT OPTIONAL */
    this.assignee = function(data) {
        if (objectCheck('assignee', data) && data.length !== 0) {
            this.rData.optionalData.assignee = data;
        }
        return this;
    };

    // this.description = function(data) {
    //     this.rData.optionalData.description = data;
    //     return this;
    // };

    this.dueDate = function(data) {
        // 2016-03-16T21:25:15Z
        this.rData.optionalData.dueDate = data;
        return this;
    };

    this.escalatee = function(data) {
        if (objectCheck('escalatee', data) && data.length !== 0) {
            this.rData.optionalData.escalatee = data;
        }
        return this;
    };

    this.escalated = function(data) {
        if (boolCheck('escalated', data)) {
            this.rData.optionalData.escalated = data;
        }
        return this;
    };

    this.escalationDate = function(data) {
        // 2016-03-16T21:25:15Z
        this.rData.optionalData.escalationDate = data;
        return this;
    };

    this.reminded = function(data) {
        if (boolCheck('reminded', data)) {
            this.rData.optionalData.reminded = data;
        }
        return this;
    };

    this.reminderDate = function(data) {
        // 2016-03-16T21:25:15Z
        this.rData.optionalData.reminderDate = data;
        return this;
    };

    this.overdue = function(data) {
        if (boolCheck('overdue', data)) {
            this.rData.optionalData.overdue = data;
        }
        return this;
    };

    this.status = function(data) {
        if (valueCheck('status', data, ['Not Started', 'In Progress', 'Complete', 'Waiting on Someone', 'Deferred'])) {
            this.rData.optionalData.status = data;
        }
        return this;
    };

    // Commit
    this.commit = function(callback) {
        /* POST - /v2/tasks */
        /* PUT - /v2/tasks/{id} */
        var _this = this;

        // validate required fields
        if (this.rData.requiredData.name) {

            // prepare body
            this.body($.extend(this.rData.requiredData, this.rData.optionalData));
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
            var errorMessage = 'Commit Failure: task name is required.';
            console.error(errorMessage);
            this.callbacks.error({error: errorMessage});
        }
    };

    // Commit Assignees
    this.commitAssignees = function(assignees) {
        /* POST - /v2/tasks/{id}/assignees/{name} */
        this.normalization(normalize.default);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'assignees',
            assignees
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('assignees');
    };

    // Commit Associations
    this.commitAssociation = function(association) {
        /* POST - /v2/tasks/{id}/groups/{type}/{id} */
        /* POST - /v2/tasks/{id}/indicators/{type}/{indicator} */
        this.normalization(normalize.find(association.type.type));
        var resourceId = association.id;
        if (association.type.type == 'URL' || association.type.type == 'EmailAddress') {
            resourceId = encodeURIComponent(association.id);
        }
        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            resourceId
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('associations');
    };

    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* POST - /v2/tasks/{id}/attributes */
        /* PUT - /v2/tasks/{id}/attributes/{id} */

        if (attribute) {
            this.normalization(normalize.attributes);

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'attributes'
            ].join('/'));
            this.requestMethod('POST');
            this.body(attribute);

            // attribute update
            if (attribute.id) {
                this.requestUri([
                    this.ajax.requestUri,
                    attribute.id,
                ].join('/'));
                this.requestMethod('PUT');
            }
            return this.apiRequest('attribute');
        }
    };

    // Commit Escalatees
    this.commitEscalatees = function(escalatees) {
        /* POST - /v2/tasks/{id}/escalatees/{name} */
        this.normalization(normalize.default);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'escalatees',
            escalatees
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('escalatees');
    };

    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* POST - /v2/tasks/{id}/securityLabel/{name} */
        this.normalization(normalize.securityLabels);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('securityLabel');
    };

    // Commit Tag
    this.commitTag = function(tag) {
        /* POST - /v2/tasks/{id}/tags/{name} */
        this.normalization(normalize.tags);

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('tag');
    };

    // Delete
    this.delete = function() {
        /* DELETE - /v2/tasks/{id} */

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id
        ].join('/'));

        this.requestMethod('DELETE');
        return this.apiRequest({action: 'delete'});
    };

    // Delete Assignees
    this.deleteAssignees = function(assignee) {
        /* DELETE - /v2/tasks/{id}/assignees/{name} */
        this.normalization(normalize.default);

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'assignees',
            assignee
            // encodeURIComponent(assignee)
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('assignee');
    };

    // Delete Associations
    this.deleteAssociation = function(association) {
        /* DELETE - /v2/tasks/{id}/groups/{type}/{id} */
        /* DELETE - /v2/tasks/{id}/indicators/{type}/{indicator} */

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('associations');
    };

    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* DELETE - /v2/tasks/{id}/attributes/{id} */

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('attribute');
    };

    // Delete Escalatees
    this.deleteEscalatees = function(escalatees) {
        /* DELETE - /v2/tasks/{id}/escalatees/{name} */
        this.normalization(normalize.default);

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'escalatees',
            escalatees
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('escalatees');
    };

    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* DELETE - /v2/tasks/{id}/securityLabel/{name} */

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('securityLabel');
    };

    // Delete Tag
    this.deleteTag = function(tag) {
        /* DELETE - /v2/tasks/{id}/tags/{name} */

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('tag');
    };

    //
    // Retrieve Security Labels
    //
    this.retrieve = function(callback) {
        /* GET - /v2/tasks/ */
        /* GET - /v2/tasks/{id}/attributes */
        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id
            ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };

    // Retrieve Assignees
    this.retrieveAssignees = function() {
        /* GET - /v2/tasks/{id}/assignees */
        this.settings.normalizer = normalize.default;
        if (this.rData.id) {
            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'assignees'
            ].join('/'));

            return this.apiRequest('assignees');
        }
    };

    // Retrieve Associations
    this.retrieveAssociations = function(association) {
        /* GET - /v2/tasks/{id}/indicators */
        /* GET - /v2/tasks/{id}/indicators/{type} */
        /* GET - /v2/tasks/{id}/groups */
        /* GET - /v2/tasks/{id}/groups/{type} */
        /* GET - /v2/tasks/{id}/victims */
        /* GET - /v2/tasks/{id}/victims/{id} */
        /* GET - /v2/tasks/{id}/victimAssets */
        /* GET - /v2/tasks/{id}/victimAssets/{type} */

        this.normalization(normalize.find(association.type.type));
        // this.normalization(normalize.find(association.type));
        this.normalizationType(association.type);

        if (this.rData.id) {
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
        }
    };

    // Retrieve Attributes
    this.retrieveAttributes = function(attributeId) {
        /* GET - /v2/tasks/{id}/attributes */
        /* GET - /v2/tasks/{id}/attributes/{id} */
        this.settings.normalizer = normalize.attributes;
        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id,
                'attributes'
            ].join('/'));
            if (attributeId !== undefined) {
                if (intCheck('attributeId', attributeId)) {
                    this.requestUri([
                        this.ajax.requestUri,
                        attributeId
                    ].join('/'));
                }
            }

            this.requestMethod('GET');

            return this.apiRequest('attributes');
        }
    };

    // Retrieve Escalatees
    this.retrieveEscalatees = function() {
        /* GET - /v2/tasks/{id}/escalatees */
        this.settings.normalizer = normalize.default;
        if (this.rData.id) {
            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'escalatees'
            ].join('/'));

            return this.apiRequest('escalatees');
        }
    };

    // Retrieve Tags
    this.retrieveTags = function(tagName) {
        /* GET - /v2/tasks/{id}/tags */
        /* GET - /v2/tasks/{id}/tags/{name} */

        this.settings.normalizer = normalize.tags;
        if (this.rData.id) {
            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'tags'
            ].join('/'));
            if (tagName) {
                this.requestUri([
                    this.ajax.requestUri,
                    tagName
                ].join('/'));
            }

            return this.apiRequest('tags');
        }
    };

    // Retrieve Security Labels
    this.retrieveSecurityLabel = function(label) {
        /* GET - /v2/tasks/{id}/securityLabel */
        /* GET - /v2/tasks/{id}/securityLabel/{name} */

        this.settings.normalizer = normalize.securityLabels;
        if (this.rData.id) {

            this.requestUri([
                this.ajax.baseUri,
                this.settings.type.uri,
                this.rData.id,
                'securityLabels'
            ].join('/'));
            if (label) {
                this.requestUri([
                    this.ajax.requestUri,
                    label
                ].join('/'));
            }

            return this.apiRequest('securityLabel');
        }
    };

    return this;
}
Tasks.prototype = Object.create(RequestObject.prototype);

function Tags(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/tags';
    this.settings.helper = true;
    this.settings.normalizer = normalize.tags;
    this.settings.type = TYPE.TAG;
    this.rData = {
        name: undefined,
    };

    /* OPTIONAL */
    this.name = function(data) {
        this.rData.name = data;
        return this;
    };

    /* All Tag commits are accessible via the individual resource commits. */
    /* All Tag deletes are accessible via the individual resource deletes. */

    // retrieve
    this.retrieve = function(callback) {
        /* GET - /v2/tags */
        /* GET - /v2/tags/{name} */

        if (this.rData.name) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.name
                ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };

    // retrieveIndicators
    this.retrieveIndicators = function(indicatorType) {
        /* GET - /v2/tags/{name}/indicators */
        /* GET - /v2/tags/{name}/indicators/{type} */

        if (!indicatorType) {
           indicatorType = TYPE.INDICATOR;
        }

        this.settings.normalizer = normalize.indicators;
        this.normalizationType(indicatorType);

        if (this.rData.name) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.name,
            ].join('/'));
        }
        if (indicatorType) {
            this.requestUri([
                this.ajax.requestUri,
                indicatorType.uri
            ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    // retrieveGroups
    this.retrieveGroups = function(groupType) {
        /* GET - /v2/tags/{name}/groups */
        /* GET - /v2/tags/{name}/groups/{type} */
        if (!groupType) {
           groupType = TYPE.GROUP;
        }

        this.settings.normalizer = normalize.groups;
        this.normalizationType(groupType);

        if (this.rData.name) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.name,
            ].join('/'));
        }
        if (groupType) {
            this.requestUri([
                this.ajax.requestUri,
                groupType.uri
            ].join('/'));
        }
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    this.retrieveTasks = function() {
        /* GET - /v2/tags/{name}/tasks */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'tasks'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    this.retrieveVictims = function() {
        /* GET - /v2/tags/{name}/victims */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'victims'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    this.retrieveVictimAssets = function() {
        /* GET - /v2/tags/{name}/victimAssets */
        this.requestUri([
            this.ajax.requestUri,
            this.rData.name,
            'victimAssets'
        ].join['/']);
        this.requestMethod('GET');

        return this.apiRequest('next');
    };

    return this;
}
Tags.prototype = Object.create(RequestObject.prototype);

function Victims(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/victims';
    this.settings.helper = true;
    this.settings.normalizer = normalize.victims;
    this.settings.type = TYPE.VICTIM;
    this.rData = {
        id: undefined,
        optionalData: {},
        requiredData: {
            name: undefined
        },
        specificData: {
            victimEmailAddress: {},
            victimNetworkAccount: {},
            victimPhone: {},
            victimSocialNetwork: {},
            victimWebSite: {},
        }
    };

    /* SETTINGS */
    this.id = function(data) {
        this.rData.id = data;
        return this;
    };

    /* REQUIRED */
    this.name = function(data) {
        this.rData.requiredData.name = data;
        return this;
    };

    /* OPTIONAL */
    this.description = function(data) {
        this.rData.optionalData.description = data;
        return this;
    };

    this.org = function(data) {
        this.rData.optionalData.org = data;
        return this;
    };

    this.suborg = function(data) {
        this.rData.optionalData.suborg = data;
        return this;
    };

    this.workLocation = function(data) {
        this.rData.optionalData.workLocation = data;
        return this;
    };

    this.nationality = function(data) {
        this.rData.optionalData.nationality = data;
        return this;
    };

    /* ASSET TYPE SPECIFIC PARAMETERS */

    // emailAddress
    this.address = function(data) {
        this.rData.specificData.victimEmailAddress.address = data;
        return this;
    };

    this.addressType = function(data) {
        this.rData.specificData.victimEmailAddress.addressType = data;
        return this;
    };

    // networkAccount / socialNetwork
    this.account = function(data) {
        this.rData.specificData.victimNetworkAccount.account = data;
        this.rData.specificData.victimSocialNetwork.account = data;
        return this;
    };

    this.network = function(data) {
        this.rData.specificData.victimNetworkAccount.network = data;
        this.rData.specificData.victimSocialNetwork.network = data;
        return this;
    };

    // phone
    this.phoneType = function(data) {
        this.rData.specificData.victimPhone.phoneType = data;
        return this;
    };

    // webSite
    this.webSite = function(data) {
        this.rData.specificData.victimWebSite.webSite = data;
        return this;
    };

    //
    // Commit Victim
    //
    this.commit = function(callback) {
        /* POST - /v2/victims */
        /* PUT - /v2/victims/{id} */
        var _this = this;

        this.requestMethod('POST');
        this.body($.extend(this.rData.requiredData, this.rData.optionalData));

        // update victim
        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id
            ].join('/'));
            this.requestMethod('PUT');
        }

        this.apiRequest({action: 'commit'})
            .done(function(response) {
                _this.rData.id = response.data[_this.settings.type.dataField].id;
                if (callback) callback();
        });
    };

    // commit victim asset
    this.commitAsset = function(assetType) {
        /* POST - /v2/victims/{id}/victimAssets/{type} */

        if (this.rData.id && assetType) {
            this.body(this.rData.specificData[assetType.dataField]);
            this.requestMethod('POST');

            this.requestUri([
                this.ajax.requestUri,
                this.rData.id,
                assetType.uri
            ].join('/'));

            return this.apiRequest('next');
        }
    };

    // Commit Associations
    this.commitAssociation = function(association) {
        /* POST - /v2/victims/{id}/groups/{type}/{id} */
        /* POST - /v2/victims/{id}/indicators/{type}/{indicators} */
        this.normalization(normalize.find(association.type.type));
        var resourceId = association.id;
        if (association.type.type == 'URL' || association.type.type == 'EmailAddress') {
            resourceId = encodeURIComponent(association.id);
        }

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            association.type.uri,
            resourceId
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('associations');
    };

    // Commit Attributes
    this.commitAttribute = function(attribute) {
        /* POST - /v2/victims/{id}/attributes */
        /* PUT - /v2/victims/{id}/attributes/{id} */
        if (attribute) {
            this.normalization(normalize.attributes);

            this.requestUri([
                this.ajax.requestUri,
                this.rData.id,
                'attributes'
            ].join('/'));
            this.requestMethod('POST');
            this.body(attribute);

            // attribute update
            if (attribute.id) {
                this.requestUri([
                    this.ajax.requestUri,
                    attribute.id,
                ].join('/'));
                this.requestMethod('PUT');
            }
            return this.apiRequest('attribute');
        }
    };

    // Commit Security Label
    this.commitSecurityLabel = function(label) {
        /* POST - /v2/victims/{id}/securityLabel/{name} */
        this.normalization(normalize.securityLabels);

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('securityLabel');
    };

    // Commit Tag
    this.commitTag = function(tag) {
        /* POST - /v2/victims/{id}/tags/{name} */
        this.normalization(normalize.tags);

        this.requestUri([
            this.ajax.requestUri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('POST');

        return this.apiRequest('tag');
    };

    // Delete
    this.delete = function() {
        /* DELETE - /v2/victims/{id} */
        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
            this.rData.id
        ].join('/'));

        this.requestMethod('DELETE');
        return this.apiRequest({
            action: 'delete'
        });
    };

    // Delete Associations
    this.deleteAssociation = function(association) {
        /* DELETE - /v2/victims/{id}/groups/{type}/{id} */
        /* DELETE - /v2/victims/{id}/indicators/{type}/{indicator} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            association.type.uri,
            association.id,
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('associations');
    };

    // Delete Attributes
    this.deleteAttribute = function(attributeId) {
        /* DELETE - /v2/victims/{id}/attributes/{id} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
            attributeId
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('attribute');
    };

    // Delete Security Label
    this.deleteSecurityLabel = function(label) {
        /* DELETE - /v2/victims/{id}/securityLabel/{name} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels',
            label
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('securityLabel');
    };

    // Delete Tag
    this.deleteTag = function(tag) {
        /* DELETE - /v2/victims/{id}/tags/{name} */

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags',
            tag
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('tag');
    };

    //
    // Retrieve Victim
    //
    this.retrieve = function(callback) {
        /* GET - /v2/victims */
        /* GET - /v2/victims/{id} */
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

    //
    // Retrieve Victim Assets
    //
    this.retrieveAssets = function(assetType) {
        /* GET - /v2/victims/{id}/victimAssets */
        /* GET - /v2/victims/{id}/victimAssets/{type} */

        if (!assetType) {
            assetType = TYPE.VICTIM_ASSET;
        }
        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id,
                assetType.uri
            ].join('/'));

            this.requestMethod('GET');
            return this.apiRequest('next');
        } else {
            console.warn('Victim ID is required.');
        }
    };

    // Retrieve Associations
    this.retrieveAssociations = function(association) {
        /* GET - /v2/victims/{id}/groups */
        /* GET - /v2/victims/{id}/groups/{type} */
        /* GET - /v2/victims/{id}/indicators */
        /* GET - /v2/victims/{id}/indicators/{type} */

        this.normalization(normalize.find(association.type.type));
        // this.normalization(normalize.find(association.type));
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
        /* GET - /v2/victims/{id}/attributes */
        /* GET - /v2/victims/{id}/attributes/{id} */
        this.settings.normalizer = normalize.attributes;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'attributes',
        ].join('/'));
        if (attributeId !== undefined) {
            if (intCheck('attributeId', attributeId)) {
                this.requestUri([
                    this.ajax.requestUri,
                    attributeId
                ].join('/'));
            }
        }

        return this.apiRequest('attribute');
    };

    // Retrieve Tags
    this.retrieveTags = function(tagName) {
        /* GET - /v2/victims/{id}/tags */
        /* GET - /v2/victims/{id}/tags/{name} */
        this.settings.normalizer = normalize.tags;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'tags'
        ].join('/'));
        if (tagName) {
            this.requestUri([
                this.ajax.requestUri,
                tagName
            ].join('/'));
        }

        return this.apiRequest('tags');
    };

    // Retrieve Tasks
    this.retrieveTasks = function() {
        /* GET - /v2/victims/{id}/tasks */

        if (this.rData.id) {
            this.requestUri([
                this.ajax.requestUri,
                this.rData.id,
                'tasks'
            ].join('/'));

            this.requestMethod('GET');
            return this.apiRequest('tasks');
        }
    };

    // Retrieve Security Labels
    this.retrieveSecurityLabel = function(label) {
        /* GET - /v2/victims/{id}/securityLabels */
        /* GET - /v2/victims/{id}/securityLabels/{label} */
        this.settings.normalizer = normalize.securityLabels;

        this.requestUri([
            this.ajax.baseUri,
            this.settings.type.uri,
            this.rData.id,
            'securityLabels'
        ].join('/'));
        if (label) {
            this.requestUri([
                this.ajax.requestUri,
                label
            ].join('/'));
        }

        return this.apiRequest('securityLabel');
    };

    return this;
}
Victims.prototype = Object.create(RequestObject.prototype);

function WhoAmI(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = 'v2';
    this.resultLimit(500);
    this.settings.helper = true;
    this.settings.type = TYPE.WHOAMI;

    /* API ACTIONS */

    // Retrieve
    this.retrieve = function(callback) {
        /* GET - /v2/whoami */

        this.requestUri([
            this.ajax.requestUri,
            this.settings.type.uri,
        ].join('/'));
        this.requestMethod('GET');
        this.settings.requestCount = this.payload.resultLimit;

        return this.apiRequest('next').done(function() {
            if (callback) {
                callback();
            }
        });
    };

    return this;
}
WhoAmI.prototype = Object.create(RequestObject.prototype);

function SecureProxy(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.defaults = {
        aysnc: true,
        contentType: undefined,
        data: undefined,
        headers: {},
        // headers: {
        //     'authorization': 'TC-Token ' + this.authentication.apiToken
        // },
        method: 'GET',
        url: undefined
    };

    this.async = function(data) {
        if (boolCheck('async', data)) {
            this.defaults.async = data;
        }
        return this;
    };

    this.body = function(data) {
        this.defaults.data = data;
        return this;
    };

    this.contentType = function(data) {
        this.defaults.contentType = data;
        return this;
    };

    this.header = function(key, val) {
        this.defaults.headers[key] = val;
        return this;
    };

    this.method = function(data) {
        if (valueCheck('method', data, ['DELETE', 'GET', 'POST', 'PUT'])) {
            this.defaults.method = data;
        }
        return this;
    };

    this.url = function(data) {
        this.defaults.url = this.secureProxy(data);
        return this;
    };

    this.request = function() {
        var _this = this;
        // console.log('this.defaults', this.defaults);

        $.ajax(this.defaults)
            .done(function (response, textStatus, request) {
                _this.callbacks.done(response);
             })
            .fail(function() {
                var message = {error: 'Request Failed.'};
                _this.callbacks.error(message);
            });
    };

    this.delete = function() {
        this.defaults.method = 'DELETE';
        this.request();
    };

    this.get = function() {
        this.defaults.method = 'GET';
        this.request();
    };

    this.post = function() {
        this.defaults.method = 'POST';
        this.request();
    };

    this.put = function() {
        this.defaults.method = 'PUT';
        this.request();
    };
}
SecureProxy.prototype = Object.create(RequestObject.prototype);

function Spaces(authentication) {
    RequestObject.call(this);

    this.authentication = authentication;
    this.ajax.requestUri = this.ajax.baseUri + '/owners';
    this.settings.helper = true;
    this.settings.normalizer = normalize.owners;
    this.settings.type = TYPE.OWNER;
    this.sData = {
        stateParams: {},
        stateText: {},
    };

    /* REQUIRED */

    this.elementId = function(data) {
        if (intCheck('elementId', data)) {
            this.spaceElementId = data;
        }
        return this;
    };

    /* OPTIONAL */

    // state optional
    this.stateParams = function(data) {
        this.sData.stateParams = data;
        return this;
    };

    // state optional
    this.expireDays = function(data) {
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
        /* GET - /v2/exchange/spaces/{element id}/file */
        /* GET - /v2/exchange/spaces/{element id}/file/{name} */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'file'
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
        /* GET - /v2/exchange/spaces/{element id}/job */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'job'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('state');
    };

    // retrieve state
    this.retrieveState = function() {
        /* GET - /v2/exchange/spaces/{element id}/state */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'state'
        ].join('/'));
        this.requestMethod('GET');

        return this.apiRequest('state');
    };

    // commit file
    this.commitFile = function(fileName) {
        /* POST - /v2/exchange/spaces/{element id}/file/{name} */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'file',
            fileName
        ].join('/'));
        this.requestMethod('POST');
        //this.contentType('application/octet-stream');
        this.contentType('multipart/form-data');

        return this.apiRequest('file');
    };

    // commit job
    this.commitJob = function() {
        /* POST - /v2/exchange/spaces/{element id}/job */
        /* POST - /v2/exchange/spaces/{element id}/job/execute */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'job'
        ].join('/'));
        var post = $.extend(this.sData.stateParams, this.sData.stateText);
        this.body(post);
        this.requestMethod('POST');
        return this.apiRequest('state');
    };

    // commit state
    this.commitState = function() {
        /* POST - /v2/exchange/spaces/{element id}/state */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'state'
        ].join('/'));
        var post = $.extend(this.sData.stateParams, this.sData.stateText);
        this.body(post);
        this.requestMethod('POST');
        return this.apiRequest('state');
    };

    // delete file
    this.deleteFile = function(fileName) {
        /* DELETE - /v2/exchange/spaces/{element id}/file/{name} */

        this.requestUri([
            'v2/exchange/spaces',
            this.spaceElementId,
            'file',
            fileName
        ].join('/'));
        this.requestMethod('DELETE');

        return this.apiRequest('file');
    };

    return this;
}
Spaces.prototype = Object.create(RequestObject.prototype);

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
            indicatorData,
            indicatorTypeData,
            indicatorType = type.type;


        if (type.dataField in response) {
            response = response[type.dataField];
            indicatorTypeData = type;
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
            if (rvalue && rvalue.length === 0) {
                return;
            }

            if ('type' in rvalue) {
                indicatorTypeData = indicatorHelper(rvalue.type.toLowerCase());
            }

            if (typeof indicatorTypeData != 'undefined'){
                indicatorType = indicatorTypeData.type;
                indicatorData = {};
                // $.each(type.indicatorFields, function(ikey, ivalue) {
                Array.prototype.forEach.call(type.indicatorFields, function(ivalue, index, array){
                    if ('summary' in rvalue) {
                        indicatorData.summary = rvalue.summary;
                        return false;
                    } else {
                        if (rvalue[ivalue]) {
                            indicatorData[ivalue] = rvalue[ivalue];
                        }
                    }
                });

                // If indicator has only one element, return as str
                if (type.indicatorFields.length == 1) {
                    indicatorData = indicatorData[type.indicatorFields[0]];
                }

                indicators.push({
                    id: rvalue.id,
                    indicator: indicatorData,
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
            }
        });

        return indicators;
    },
    indicatorsBatch: function(type, response) {

        response = response.indicator;

        var indicators = [];
        // $.each(response, function(rkey, rvalue) {
        Array.prototype.forEach.call(response, function(rvalue, index, array){
            if (rvalue && rvalue.length === 0) {
                return;
            }

            rvalue.indicator = rvalue.summary;
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
        var observationCount;

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
    tasks: function(type, response) {
        var tasks = [];

        if (response) {
            tasks = response.task;
        }
        return tasks;
    },
    victims: function(type, response) {
        var victims = [];

        if (response) {
            victims = response.victim;
        }
        return victims;
    },
    default: function(type, response) {
        return response;
    },
    find: function(type) {

        switch (type) {
            case TYPE.ADVERSARY.type:
            case TYPE.CAMPAIGN.type:
            case TYPE.DOCUMENT.type:
            case TYPE.EMAIL.type:
            case TYPE.EVENT.type:
            case TYPE.GROUP.type:
            case TYPE.INCIDENT.type:
            case TYPE.INTRUSION_SET.type:
            case TYPE.REPORT.type:
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
            case TYPE.VICTIM.type:
                return this.victims;
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
    /* validate user input is a function */

    if (typeof value == 'function') {
        return true;
    }
    console.error(name + ' must be of type function.');
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

var objectCheck = function(name, value) {
    /* validate user input is an object */

    if (typeof value == 'object') {
        return true;
    }
    console.error(name + ' must be of type object.');
    return false;
};

var rangeCheck = function(name, value, low, high) {
    /* validate user input is in appropriate range */

    if (!isNaN(value) && !isNaN(low) && !isNaN(high)) {
        if (low >= value <= high) {
            return true;
        }
    }
    console.warn(name + ' must be of type integer between ' + low + ' and ' + high + '.');
    return false;
};

var requiredCheck = function(name, data) {
    /* validate user input a valid values */

    if (data[name]) {
        return true;
    }
    console.warn(name + ' paramater is required.');
    return false;
};

var valueCheck = function(name, value, array) {
    /* validate user input matches predefined values */

    if ($.inArray(value, array) != -1) {
        return true;
    }
    console.warn(name + ' must be of value (.' + array.join(',') + ').');
    return false;
};
