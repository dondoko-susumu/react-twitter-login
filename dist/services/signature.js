"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_js_1 = require("crypto-js");
exports.requestTokenSignature = function (_a) {
    var method = _a.method, apiUrl = _a.apiUrl, callbackUrl = _a.callbackUrl, consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret;
    var params = {
        oauth_consumer_key: consumerKey,
        oauth_version: "1.0",
        oauth_signature_method: "HMAC-SHA1",
        oauth_callback: callbackUrl,
        oauth_timestamp: (Date.now() / 1000).toFixed(),
        oauth_nonce: Math.random()
            .toString(36)
            .replace(/[^a-z]/, "")
            .substr(2)
    };
    return makeSignature(params, method, apiUrl, consumerSecret);
};
exports.accessTokenSignature = function (_a) {
    var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, oauthToken = _a.oauthToken, oauthVerifier = _a.oauthVerifier, method = _a.method, apiUrl = _a.apiUrl;
    var params = {
        oauth_consumer_key: consumerKey,
        oauth_version: "1.0",
        oauth_signature_method: "HMAC-SHA1",
        oauth_token: oauthToken,
        oauth_verifier: oauthVerifier,
        oauth_timestamp: (Date.now() / 1000).toFixed(),
        oauth_nonce: Math.random()
            .toString(36)
            .replace(/[^a-z]/, "")
            .substr(2)
    };
    return makeSignature(params, method, apiUrl, consumerSecret);
};
exports.accessResourceSignature = function (_a) {
    var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, oauthToken = _a.oauthToken, oauthTokenSecret = _a.oauthTokenSecret, method = _a.method, apiUrl = _a.apiUrl, include_email = _a.include_email;
    var params = {
        oauth_consumer_key: consumerKey,
        oauth_version: "1.0",
        oauth_signature_method: "HMAC-SHA1",
        oauth_token: oauthToken,
        oauth_timestamp: (Date.now() / 1000).toFixed(),
        oauth_nonce: Math.random()
            .toString(36)
            .replace(/[^a-z]/, "")
            .substr(2)
    };
    var queryParams = {
        include_email: include_email
    };
    return makeSignature(params, method, apiUrl, consumerSecret, oauthTokenSecret, queryParams);
};
var makeSignature = function (params, method, apiUrl, consumerSecret, oauthTokenSecret, queryParams) {
    var paramsBaseString;
    var _params = params;
    if (queryParams) {
        _params = __assign(__assign({}, _params), queryParams);
    }
    paramsBaseString = Object.keys(_params)
        .sort()
        .reduce(function (prev, el) {
        return (prev += "&" + el + "=" + _params[el]);
    }, "")
        .substr(1);
    var signatureBaseString = method.toUpperCase() + "&" + encodeURIComponent(apiUrl) + "&" + encodeURIComponent(paramsBaseString);
    var signingKey = encodeURIComponent(consumerSecret) + "&";
    if (oauthTokenSecret) {
        signingKey = "" + signingKey + encodeURIComponent(oauthTokenSecret);
    }
    var oauth_signature = crypto_js_1.enc.Base64.stringify(crypto_js_1.HmacSHA1(signatureBaseString, signingKey));
    var paramsWithSignature = __assign(__assign({}, params), { oauth_signature: encodeURIComponent(oauth_signature) });
    return Object.keys(paramsWithSignature)
        .sort()
        .reduce(function (prev, el) {
        return (prev += "," + el + "=\"" + paramsWithSignature[el] + "\"");
    }, "")
        .substr(1);
};
//# sourceMappingURL=signature.js.map