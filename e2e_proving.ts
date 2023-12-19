import {
  MembershipProver,
  MembershipVerifier,
  Poseidon,
  Tree,
  ProverConfig,
  VerifyConfig
} from "@personaelabs/spartan-ecdsa";
import { hashPersonalMessage, privateToAddress, ecsign, toRpcSig } from "@ethereumjs/util";



const hushProofProverConfigDefault: ProverConfig = {
  witnessGenWasm:
    "./addr_membership.wasm",
  circuit:
    "./addr_membership.circuit"
};

const hushProofVerifierConfigDefault: VerifyConfig = {
  circuit: hushProofProverConfigDefault.circuit
};


const proveMembership = async () => {


  // Init the Poseidon hash
  const poseidon = new Poseidon();
  await poseidon.initWasm();

  const treeDepth = 20; // Provided circuits have tree depth = 20
  const tree = new Tree(treeDepth, poseidon);

  const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
  const address = privateToAddress(privKey);

  // Get the prover public key hash
  const proverAddress = BigInt("0x" + Buffer.from(address).toString("hex"));

  // Insert prover public key hash into the tree
  tree.insert(proverAddress);


  // Insert other members into the tree
  for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
    tree.insert(
      BigInt(
        "0x" + Buffer.from("".padStart(16, member), "utf16le").toString("hex")
      )
    );
  }

  // Compute the merkle proof
  const index = tree.indexOf(proverAddress);
  const merkleProof = tree.createProof(index);

  // Init the prover
  const prover = new MembershipProver(hushProofProverConfigDefault);
  await prover.initWasm();

  const msgHash = hashPersonalMessage(Buffer.from("harry potter"));

  const { v, r, s } = ecsign(msgHash, privKey);

  // Convert to RPC signature format
  const sig = toRpcSig(v, r, s);

  // Prove membership
  const { proof, publicInput } = await prover.prove(sig, Buffer.from(msgHash), merkleProof);

  // Init verifier
  const verifier = new MembershipVerifier(hushProofVerifierConfigDefault);
  await verifier.initWasm();

  // Verify proof
  await verifier.verify(proof, publicInput.serialize());
};

proveMembership().then(() => console.log("done"));