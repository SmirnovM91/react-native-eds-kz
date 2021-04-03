"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signXMLData = exports.authXMLData = exports.signPlainData = exports.authPlainData = void 0;
const react_native_1 = require("react-native");
const { Rnedskz } = react_native_1.NativeModules;
const callback = (err, result, resolve, reject) => {
    if (err) {
        return reject(err);
    }
    resolve(result);
};
function authPlainData({ path, password, data, }) {
    return new Promise((resolve, reject) => {
        Rnedskz.authPlainData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
}
exports.authPlainData = authPlainData;
function signPlainData({ path, password, data, }) {
    return new Promise((resolve, reject) => {
        Rnedskz.signPlainData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
}
exports.signPlainData = signPlainData;
function authXMLData({ path, password, data, }) {
    return new Promise((resolve, reject) => {
        Rnedskz.authXMLData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
}
exports.authXMLData = authXMLData;
function signXMLData({ path, password, data, }) {
    return new Promise((resolve, reject) => {
        Rnedskz.signXMLData(path, password, data, (err, result) => callback(err, result, resolve, reject));
    });
}
exports.signXMLData = signXMLData;
const RNEDS = { signPlainData, authPlainData, signXMLData, authXMLData };
exports.default = RNEDS;
