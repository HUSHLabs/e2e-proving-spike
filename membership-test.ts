// const wasm_tester = require("circom_tester").wasm;

import { wasm as wasm_tester } from "circom_tester";
import { ec as EC } from "elliptic";
import * as path from "path";
import { privateToAddress, hashPersonalMessage, ecsign } from "@ethereumjs/util";
// import * as assert from "assert";
import { Poseidon, Tree, computeEffEcdsaPubInput } from "@personaelabs/spartan-ecdsa";
import { verify } from "crypto";

const ec = new EC("secp256k1");

const getEffEcdsaCircuitInput = (privKey: Buffer, msg: Buffer) => {
  const msgHash = hashPersonalMessage(msg);
  const { v, r: _r, s } = ecsign(msgHash, privKey);
  const r = BigInt("0x" + Buffer.from(_r).toString("hex"));

  const circuitPubInput = computeEffEcdsaPubInput(r, v, Buffer.from(msgHash));
  const input = {
    s: BigInt("0x" + Buffer.from(s).toString("hex")),
    Tx: circuitPubInput.Tx,
    Ty: circuitPubInput.Ty,
    Ux: circuitPubInput.Ux,
    Uy: circuitPubInput.Uy
  };

  return input;
};

 const bytesToBigInt = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).toString("hex"));

 const verifyMembership = async () => {
    // Compile the circuit
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/addr_membership_test.circom"),
      {
        prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
      }
    );

    // Construct the tree
    const poseidon = new Poseidon();
    await poseidon.initWasm();

    const nLevels = 10;
    const tree = new Tree(nLevels, poseidon);

    const privKeys = [
      Buffer.from("".padStart(16, "🧙"), "utf16le"),
      Buffer.from("".padStart(16, "🪄"), "utf16le"),
      Buffer.from("".padStart(16, "🔮"), "utf16le")
    ];

    // Store addresses hashes
    const addresses: bigint[] = [];

    // Compute public key hashes
    for (const privKey of privKeys) {
      const address = privateToAddress(privKey);
      addresses.push(BigInt("0x" + Buffer.from(address).toString("hex")));
    }

    // Insert the pubkey hashes into the tree
    for (const address of addresses) {
      tree.insert(address);
    }

    console.log("Sanity check (check that there are not duplicate members)", 
    new Set(addresses).size === addresses.length);

    // Sign
    const index = 0; // Use privKeys[0] for proving
    const privKey = privKeys[index];
    const msg = Buffer.from("hello world");

    // Prepare signature proof input
    const effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);

    const merkleProof = tree.createProof(index);

    const input = {
      ...effEcdsaInput,
      siblings: merkleProof.siblings,
      pathIndices: merkleProof.pathIndices,
      root: tree.root()
    };

    // Generate witness
    const w = await circuit.calculateWitness(input, true);

    await circuit.checkConstraints(w);
  };

const verifyMembership32k = async () => {
    // Compile the circuit
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/addr_membership_test.circom"),
      {
        prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
      }
    );

    // Construct the tree
    const poseidon = new Poseidon();
    await poseidon.initWasm();

    const nLevels = 15; // Increase the number of levels to 15
    const tree = new Tree(nLevels, poseidon);

    // Generate 32,000 private keys and addresses
    const privKeys = Array.from({ length: 32000 }, (_, i) =>
      Buffer.from(i.toString().padStart(16, "0"), "utf16le")
    );

    // Store addresses hashes
    const addresses: bigint[] = [];

    // Compute public key hashes
    for (const privKey of privKeys) {
      const address = privateToAddress(privKey);
      addresses.push(BigInt("0x" + Buffer.from(address).toString('hex')));
    }

    // Insert the pubkey hashes into the tree
    for (const address of addresses) {
      tree.insert(address);
    }

    console.log("Sanity check (check that there are not duplicate members)",
    new Set(addresses).size === addresses.length);

    // Sign
    const index = 0; // Use privKeys[0] for proving
    const privKey = privKeys[index];
    const msg = Buffer.from("hello world");

    // Prepare signature proof input
    const effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);

    const merkleProof = tree.createProof(index);

    const input = {
      ...effEcdsaInput,
      siblings: merkleProof.siblings,
      pathIndices: merkleProof.pathIndices,
      root: tree.root()
    };

    // Generate witness
    const w = await circuit.calculateWitness(input, true);

    await circuit.checkConstraints(w);
  };


// Run the test
verifyMembership().then(() => console.log("Membership test passed!")).catch((err) => console.log(err));
verifyMembership32k().then(() => console.log("Membership32k test passed!")).catch((err) => console.log(err));