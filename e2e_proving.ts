import {
  MembershipProver,
  MembershipVerifier,
  Poseidon,
  Tree,
  ProverConfig,
  VerifyConfig
} from "@personaelabs/spartan-ecdsa";
import { hashPersonalMessage, privateToAddress, ecsign, toRpcSig } from "@ethereumjs/util";
import chalk from "chalk";
import figlet from "figlet";
const hushProofProverConfigDefault: ProverConfig = {
  witnessGenWasm: "./addr_membership.wasm",
  circuit: "./addr_membership.circuit"
};

const hushProofVerifierConfigDefault: VerifyConfig = {
  circuit: hushProofProverConfigDefault.circuit
};

const printHeader = (text: string) => {
  console.log(chalk.bold.blue(figlet.textSync(text)));
};

const printStep = (text: string) => {
  console.log(chalk.yellow(`\n${text}\n`));
};

const printDataStructure = (text: string) => {
  console.log(chalk.green(`\n${text}\n`));
};

const proveMembership = async () => {
  printHeader("HushProof PoC");

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
  printStep("Inserting Prover Public Key Hash into the Tree");

  printStep("Generating 4096 Ethereum Addresses, with pool of addresses this large it should be infeasible to find out which address is the prover's address.");

  // Generate private keys and addresses
  const privKeys = Array.from({ length: 4095 }, (_, i) => {
    const privKey = Buffer.from(i.toString().padStart(16, "0"), "utf16le");
    const address = privateToAddress(privKey);
    process.stdout.write(`Generated address ${i + 1}: ${chalk.green(`${"0x" + Buffer.from(address).toString("hex")}\r`)}`);
    return privKey;
  });

  // Store addresses hashes
  const addresses: bigint[] = [];

  // Compute public key hashes
  for (const privKey of privKeys) {
    const address = privateToAddress(privKey);
    addresses.push(BigInt("0x" + Buffer.from(address).toString("hex")));
  }
  
  const progressBar = (current: number, total: number, address: string) => {
    const percentage = Math.floor((current / total) * 100);
    process.stdout.write(`\rInserting address ${current + 1} to tree: [${'='.repeat(percentage / 5)}${' '.repeat(20 - percentage / 5)}] ${percentage}% - Ethereum Address: ${chalk.green(address)}`);
  };

  const insertPubKeyHashes = () => {
    for (let i = 0; i < addresses.length; i++) {
      const address = addresses[i];
      tree.insert(address);
      progressBar(i + 1, addresses.length, "0x" + address.toString(16));
    }
  };

  await insertPubKeyHashes();
  console.log("\n")

  console.log(chalk.cyan("Sanity check (check that there are not duplicate members)"));
  console.log(chalk.cyan(new Set(addresses).size === addresses.length));

  // Compute the merkle proof
  const index = tree.indexOf(proverAddress);
  const merkleProof = tree.createProof(index);

  printStep("Computing Merkle Proof");
  // console.log(chalk.cyan("Merkle Proof:"));
  // console.log(merkleProof);

  // Init the prover
  const prover = new MembershipProver(hushProofProverConfigDefault);
  await prover.initWasm();

  printStep("Generating Signature, prover now signs a message with his private key and generates a signature.");

  const msgHash = hashPersonalMessage(Buffer.from("harry potter"));

  const { v, r, s } = ecsign(msgHash, privKey);

  // Convert to RPC signature format
  const sig = toRpcSig(v, r, s);

  // Prove membership
  const { proof, publicInput } = await prover.prove(sig, Buffer.from(msgHash), merkleProof);

  printStep("Proving Membership, prover now proves that he is a member of the subset of addresses and has signed the message.");

  console.log(chalk.cyan("Proof:"));
  console.log(proof);
  console.log(chalk.cyan("Public Input:"));
  console.log(publicInput.serialize());

  // Init verifier
  const verifier = new MembershipVerifier(hushProofVerifierConfigDefault);
  await verifier.initWasm();

  // Verify proof
  await verifier.verify(proof, publicInput.serialize());

  console.log(chalk.green("\nDone"));
};

proveMembership().catch((error) => console.error(chalk.red(error)));
