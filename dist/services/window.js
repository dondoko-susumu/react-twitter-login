"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.openWindow = function (_a) {
    var url = _a.url, name = _a.name;
    var top = (window.innerHeight - 400) / 2 + window.screenY;
    var left = (window.innerWidth - 400) / 2 + window.screenX;
    return window.open(url, name, "dialog=yes,top=" + top + "px,left=" + left + ",width=" + 400 + "px,height=" + 500 + "px");
};
exports.observeWindow = function (_a) {
    var popup = _a.popup, interval = _a.interval, onClose = _a.onClose;
    var intervalId = setInterval(function () {
        if (popup.closed) {
            clearInterval(intervalId);
            onClose();
        }
    }, interval || 100);
};
//# sourceMappingURL=window.js.map