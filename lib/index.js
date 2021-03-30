"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signPlainData = exports.authPlainData = void 0;
const react_native_1 = require("react-native");
const { Rnedskz } = react_native_1.NativeModules;
const callback = (err, result, resolve, reject) => {
    if (err) {
        return reject(err);
    }
    resolve(result);
};
exports.authPlainData = ({ path, password, data, }) => {
    return new Promise((resolve, reject) => {
        Rnedskz.authPlainData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
};
exports.signPlainData = ({ path, password, data, }) => {
    return new Promise((resolve, reject) => {
        Rnedskz.signPlainData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
};
exports.default = Rnedskz;
