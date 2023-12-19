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
  printHeader("Proving Membership");

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
  printDataStructure(tree.toString());

  // // Insert other members into the tree
  // for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
  //   tree.insert(
  //     BigInt(
  //       "0x" + Buffer.from("".padStart(16, member), "utf16le").toString("hex")
  //     )
  //   );
  // }

  // printStep("Inserting Other Members into the Tree");
  // printDataStructure(tree.toString());

  // Generate 32,000 private keys and addresses
  const privKeys = Array.from({ length: 1023 }, (_, i) => {
    const privKey = Buffer.from(i.toString().padStart(16, "0"), "utf16le");
    const address = privateToAddress(privKey);
    console.log(chalk.yellow(`Generated address: ${"0x" + Buffer.from(address).toString("hex")}`));
    return privKey;
  });

  // Store addresses hashes
  const addresses: bigint[] = [];

  // Compute public key hashes
  for (const privKey of privKeys) {
    const address = privateToAddress(privKey);
    addresses.push(BigInt("0x" + Buffer.from(address).toString("hex")));
  }

  const progressBarDraw = (current: number, total: number) => {
    const percentage = Math.floor((current / total) * 100);
    process.stdout.clearLine(0);
    process.stdout.cursorTo(0);
    const progressBar = (current: number, total: number) => {
      const percentage = Math.floor((current / total) * 100);
      const filledLength = Math.floor(percentage / 10);
      const bar = '='.repeat(filledLength) + ' '.repeat(10 - filledLength);
      process.stdout.write(`Progress: [${bar}] ${percentage}%\r`);
    };
  }

    // Insert the pubkey hashes into the tree
    for (let i = 0; i < addresses.length; i++) {
      tree.insert(addresses[i]);
      progressBarDraw(i + 1, addresses.length);
    }

    printStep("Inserting Public Key Hashes into the Tree");
    printDataStructure(tree.toString());

    console.log(chalk.cyan("Sanity check (check that there are not duplicate members)"));
    console.log(chalk.cyan(new Set(addresses).size === addresses.length));

    // Compute the merkle proof
    const index = tree.indexOf(proverAddress);
    const merkleProof = tree.createProof(index);

    printStep("Computing Merkle Proof");
    console.log(chalk.cyan("Merkle Proof:"));
    console.log(merkleProof);

    // Init the prover
    const prover = new MembershipProver(hushProofProverConfigDefault);
    await prover.initWasm();

    const msgHash = hashPersonalMessage(Buffer.from("harry potter"));

    const { v, r, s } = ecsign(msgHash, privKey);

    // Convert to RPC signature format
    const sig = toRpcSig(v, r, s);

    // Prove membership
    const { proof, publicInput } = await prover.prove(sig, Buffer.from(msgHash), merkleProof);

    printStep("Proving Membership");
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
