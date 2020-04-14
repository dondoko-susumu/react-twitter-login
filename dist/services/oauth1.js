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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var signature_1 = require("./signature");
var parseOAuthRequestToken = function (responseText) {
    return responseText.split("&").reduce(function (prev, el) {
        var _a;
        var _b = el.split("="), key = _b[0], value = _b[1];
        return __assign(__assign({}, prev), (_a = {}, _a[key] = value, _a));
    }, {});
};
exports.obtainOauthRequestToken = function (_a) {
    var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, callbackUrl = _a.callbackUrl, method = _a.method, apiUrl = _a.apiUrl;
    return __awaiter(void 0, void 0, void 0, function () {
        var oauthSignature, res, responseText;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    oauthSignature = signature_1.requestTokenSignature({
                        method: method,
                        apiUrl: apiUrl,
                        callbackUrl: callbackUrl,
                        consumerKey: consumerKey,
                        consumerSecret: consumerSecret
                    });
                    return [4, fetch("https://cors-anywhere.herokuapp.com/" + apiUrl, {
                            method: method,
                            headers: {
                                Authorization: "OAuth " + oauthSignature
                            }
                        })];
                case 1:
                    res = _b.sent();
                    return [4, res.text()];
                case 2:
                    responseText = _b.sent();
                    return [2, parseOAuthRequestToken(responseText)];
            }
        });
    });
};
exports.obtainOauthAccessToken = function (_a) {
    var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, oauthToken = _a.oauthToken, oauthVerifier = _a.oauthVerifier, method = _a.method, apiUrl = _a.apiUrl;
    return __awaiter(void 0, void 0, void 0, function () {
        var oauthSignature, res, responseText;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    oauthSignature = signature_1.accessTokenSignature({
                        method: method,
                        apiUrl: apiUrl,
                        consumerKey: consumerKey,
                        consumerSecret: consumerSecret,
                        oauthToken: oauthToken,
                        oauthVerifier: oauthVerifier
                    });
                    return [4, fetch("https://cors-anywhere.herokuapp.com/" + apiUrl, {
                            method: method,
                            headers: {
                                Authorization: "OAuth " + oauthSignature
                            }
                        })];
                case 1:
                    res = _b.sent();
                    return [4, res.text()];
                case 2:
                    responseText = _b.sent();
                    return [2, parseOAuthRequestToken(responseText)];
            }
        });
    });
};
exports.obtainTwitterAccount = function (_a) {
    var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, oauthToken = _a.oauthToken, oauthTokenSecret = _a.oauthTokenSecret, method = _a.method, apiUrl = _a.apiUrl, include_email = _a.include_email;
    return __awaiter(void 0, void 0, void 0, function () {
        var oauthSignature, res, responseJson;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    oauthSignature = signature_1.accessResourceSignature({
                        method: method,
                        apiUrl: apiUrl,
                        consumerKey: consumerKey,
                        consumerSecret: consumerSecret,
                        oauthToken: oauthToken,
                        oauthTokenSecret: oauthTokenSecret,
                        include_email: include_email
                    });
                    return [4, fetch("https://cors-anywhere.herokuapp.com/" + apiUrl + "?include_email=" + include_email, {
                            method: method,
                            headers: {
                                Authorization: "OAuth " + oauthSignature
                            }
                        })];
                case 1:
                    res = _b.sent();
                    return [4, res.json()];
                case 2:
                    responseJson = _b.sent();
                    return [2, responseJson];
            }
        });
    });
};
//# sourceMappingURL=oauth1.js.map