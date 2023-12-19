"use strict";
// const wasm_tester = require("circom_tester").wasm;
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
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
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
var circom_tester_1 = require("circom_tester");
var elliptic_1 = require("elliptic");
var path = require("path");
var util_1 = require("@ethereumjs/util");
// import * as assert from "assert";
var spartan_ecdsa_1 = require("@personaelabs/spartan-ecdsa");
var ec = new elliptic_1.ec("secp256k1");
var getEffEcdsaCircuitInput = function (privKey, msg) {
    var msgHash = (0, util_1.hashPersonalMessage)(msg);
    var _a = (0, util_1.ecsign)(msgHash, privKey), v = _a.v, _r = _a.r, s = _a.s;
    var r = BigInt("0x" + Buffer.from(_r).toString("hex"));
    var circuitPubInput = (0, spartan_ecdsa_1.computeEffEcdsaPubInput)(r, v, Buffer.from(msgHash));
    var input = {
        s: BigInt("0x" + Buffer.from(s).toString("hex")),
        Tx: circuitPubInput.Tx,
        Ty: circuitPubInput.Ty,
        Ux: circuitPubInput.Ux,
        Uy: circuitPubInput.Uy
    };
    return input;
};
var bytesToBigInt = function (bytes) {
    return BigInt("0x" + Buffer.from(bytes).toString("hex"));
};
var verifyMembership = function () { return __awaiter(void 0, void 0, void 0, function () {
    var circuit, poseidon, nLevels, tree, privKeys, addresses, _i, privKeys_1, privKey_1, address, _a, addresses_1, address, index, privKey, msg, effEcdsaInput, merkleProof, input, w;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, (0, circom_tester_1.wasm)(path.join(__dirname, "./circuits/addr_membership_test.circom"), {
                    prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
                })];
            case 1:
                circuit = _b.sent();
                poseidon = new spartan_ecdsa_1.Poseidon();
                return [4 /*yield*/, poseidon.initWasm()];
            case 2:
                _b.sent();
                nLevels = 10;
                tree = new spartan_ecdsa_1.Tree(nLevels, poseidon);
                privKeys = [
                    Buffer.from("".padStart(16, "🧙"), "utf16le"),
                    Buffer.from("".padStart(16, "🪄"), "utf16le"),
                    Buffer.from("".padStart(16, "🔮"), "utf16le")
                ];
                addresses = [];
                // Compute public key hashes
                for (_i = 0, privKeys_1 = privKeys; _i < privKeys_1.length; _i++) {
                    privKey_1 = privKeys_1[_i];
                    address = (0, util_1.privateToAddress)(privKey_1);
                    addresses.push(BigInt("0x" + Buffer.from(address).toString("hex")));
                }
                // Insert the pubkey hashes into the tree
                for (_a = 0, addresses_1 = addresses; _a < addresses_1.length; _a++) {
                    address = addresses_1[_a];
                    tree.insert(address);
                }
                console.log("Sanity check (check that there are not duplicate members)", new Set(addresses).size === addresses.length);
                index = 0;
                privKey = privKeys[index];
                msg = Buffer.from("hello world");
                effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);
                merkleProof = tree.createProof(index);
                input = __assign(__assign({}, effEcdsaInput), { siblings: merkleProof.siblings, pathIndices: merkleProof.pathIndices, root: tree.root() });
                return [4 /*yield*/, circuit.calculateWitness(input, true)];
            case 3:
                w = _b.sent();
                return [4 /*yield*/, circuit.checkConstraints(w)];
            case 4:
                _b.sent();
                return [2 /*return*/];
        }
    });
}); };
var verifyMembership32k = function () { return __awaiter(void 0, void 0, void 0, function () {
    var circuit, poseidon, nLevels, tree, privKeys, addresses, _i, privKeys_2, privKey_2, address, _a, addresses_2, address, index, privKey, msg, effEcdsaInput, merkleProof, input, w;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, (0, circom_tester_1.wasm)(path.join(__dirname, "./circuits/addr_membership_test.circom"), {
                    prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
                })];
            case 1:
                circuit = _b.sent();
                poseidon = new spartan_ecdsa_1.Poseidon();
                return [4 /*yield*/, poseidon.initWasm()];
            case 2:
                _b.sent();
                nLevels = 15;
                tree = new spartan_ecdsa_1.Tree(nLevels, poseidon);
                privKeys = Array.from({ length: 32000 }, function (_, i) {
                    return Buffer.from(i.toString().padStart(16, "0"), "utf16le");
                });
                addresses = [];
                // Compute public key hashes
                for (_i = 0, privKeys_2 = privKeys; _i < privKeys_2.length; _i++) {
                    privKey_2 = privKeys_2[_i];
                    address = (0, util_1.privateToAddress)(privKey_2);
                    addresses.push(BigInt("0x" + Buffer.from(address).toString('hex')));
                }
                // Insert the pubkey hashes into the tree
                for (_a = 0, addresses_2 = addresses; _a < addresses_2.length; _a++) {
                    address = addresses_2[_a];
                    tree.insert(address);
                }
                console.log("Sanity check (check that there are not duplicate members)", new Set(addresses).size === addresses.length);
                index = 0;
                privKey = privKeys[index];
                msg = Buffer.from("hello world");
                effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);
                merkleProof = tree.createProof(index);
                input = __assign(__assign({}, effEcdsaInput), { siblings: merkleProof.siblings, pathIndices: merkleProof.pathIndices, root: tree.root() });
                return [4 /*yield*/, circuit.calculateWitness(input, true)];
            case 3:
                w = _b.sent();
                return [4 /*yield*/, circuit.checkConstraints(w)];
            case 4:
                _b.sent();
                return [2 /*return*/];
        }
    });
}); };
// Run the test
verifyMembership().then(function () { return console.log("Membership test passed!"); }).catch(function (err) { return console.log(err); });
verifyMembership32k().then(function () { return console.log("Membership32k test passed!"); }).catch(function (err) { return console.log(err); });
