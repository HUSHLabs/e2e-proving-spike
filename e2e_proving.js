"use strict";
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
var spartan_ecdsa_1 = require("@personaelabs/spartan-ecdsa");
var util_1 = require("@ethereumjs/util");
var proveMembership = function () { return __awaiter(void 0, void 0, void 0, function () {
    var poseidon, treeDepth, tree, proverAddress, _i, _a, member, index, merkleProof, prover, sig, msgHash, _b, proof, publicInput, verifier;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                poseidon = new spartan_ecdsa_1.Poseidon();
                return [4 /*yield*/, poseidon.initWasm()];
            case 1:
                _c.sent();
                treeDepth = 20;
                tree = new spartan_ecdsa_1.Tree(treeDepth, poseidon);
                proverAddress = BigInt("0x...");
                // Insert prover public key hash into the tree
                tree.insert(proverAddress);
                // Insert other members into the tree
                for (_i = 0, _a = ["🕵️", "🥷", "👩‍🔬"]; _i < _a.length; _i++) {
                    member = _a[_i];
                    tree.insert(BigInt("0x" + Buffer.from("".padStart(16, member), "utf16le").toString("hex")));
                }
                index = tree.indexOf(proverAddress);
                merkleProof = tree.createProof(index);
                prover = new spartan_ecdsa_1.MembershipProver(spartan_ecdsa_1.defaultAddressMembershipPConfig);
                return [4 /*yield*/, prover.initWasm()];
            case 2:
                _c.sent();
                sig = "0x...";
                msgHash = (0, util_1.hashPersonalMessage)(Buffer.from("harry potter"));
                return [4 /*yield*/, prover.prove(sig, Buffer.from(msgHash), merkleProof)];
            case 3:
                _b = _c.sent(), proof = _b.proof, publicInput = _b.publicInput;
                verifier = new spartan_ecdsa_1.MembershipVerifier(spartan_ecdsa_1.defaultAddressMembershipVConfig);
                return [4 /*yield*/, verifier.initWasm()];
            case 4:
                _c.sent();
                // Verify proof
                return [4 /*yield*/, verifier.verify(proof, publicInput.serialize())];
            case 5:
                // Verify proof
                _c.sent();
                return [2 /*return*/];
        }
    });
}); };
proveMembership().then(function () { return console.log("done"); });
