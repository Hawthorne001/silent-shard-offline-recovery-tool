import { SLIP10Node, secp256k1 } from "@metamask/key-tree";
import {
  concatBytes,
  stringToBytes,
  hexToBytes,
  hexToBigInt,
  bigIntToBytes,
  bytesToHex,
  bigIntToHex,
} from "@metamask/utils";
import { keccak_256 as keccak256 } from "@noble/hashes/sha3";
import canonicalSerialize from "./canonicalize";
import sodium from "libsodium-wrappers";

export type SnapBackup = {
  version: number;
  time: string;
  wallet: {
    address: string;
    keyshare: string;
    remote: string;
  }[];
  hash: string;
};

export type ExportedKey = {
  address: string;
  privateKey: string;
};

const MAGIC_VALUE = 0xd36e6170;
const HARDENED_VALUE = 0x80000000;
const SNAP_ID = "npm:@silencelaboratories/silent-shard-snap";

/**
 * Get an array of `uint32 | 0x80000000` values from a hash. The hash is assumed
 * to be 32 bytes long.
 *
 * @param hash - The hash to derive indices from.
 * @returns The derived indices.
 */
const getUint32Array = (hash: Uint8Array) => {
  const array = [];
  const view = new DataView(hash.buffer, hash.byteOffset, hash.byteLength);

  for (let index = 0; index < 8; index++) {
    const uint32 = view.getUint32(index * 4);
    array.push((uint32 | HARDENED_VALUE) >>> 0);
  }

  return array;
};

/**
 * Get a BIP-32 derivation path, compatible with `@metamask/key-tree`, from an
 * array of indices. The indices are assumed to be a `uint32 | 0x80000000`.
 *
 * @param indices - The indices to get the derivation path for.
 * @returns The derivation path.
 */
const getDerivationPath = (indices: number[]) => {
  return indices.map((index) => `bip32:${index - HARDENED_VALUE}'` as const);
};

/**
 * Derive deterministic Snap-specific entropy from a mnemonic phrase. The
 * snap ID and salt are used to derive a BIP-32 derivation path, which is then
 * used to derive a private key from the mnemonic phrase.
 *
 * The derived private key is returned as entropy.
 *
 * @param mnemonicPhrase - The mnemonic phrase to derive entropy from.
 * @param snapId - The ID of the Snap.
 * @param salt - An optional salt to use in the derivation. If not provided, an
 * empty string is used.
 * @returns The derived entropy.
 */
async function getEntropy(
  mnemonicPhrase: string,
  snapId: string,
  salt = "",
): Promise<string> {
  const snapIdBytes = stringToBytes(snapId);
  const saltBytes = stringToBytes(salt);

  // Get the derivation path from the snap ID.
  const hash = keccak256(concatBytes([snapIdBytes, keccak256(saltBytes)]));
  const computedDerivationPath = getUint32Array(hash);

  // Derive the private key using BIP-32.
  const { privateKey } = await SLIP10Node.fromDerivationPath({
    derivationPath: [
      `bip39:${mnemonicPhrase}`,
      ...getDerivationPath([MAGIC_VALUE, ...computedDerivationPath]),
    ],
    curve: "secp256k1",
  });

  if (!privateKey) {
    throw new Error("Failed to derive private key.");
  }

  return privateKey;
}

/**
 * Decrypt Snap backup data using the derived entropy from a mnemonic phrase.
 * @param entropyHex Derived entropy from mnemonic phrase
 * @param snapBackup Snap backup data
 * @returns Decrypted Snap backup data
 */
async function decSnapBackup(
  entropyHex: string,
  snapBackup: string,
): Promise<Uint8Array> {
  try {
    if (entropyHex.startsWith("0x")) {
      entropyHex = entropyHex.slice(2);
    }

    await sodium.ready;
    const array = snapBackup.split(".");
    if (array.length !== 3) {
      throw new Error("Invalid backup data");
    }
    const encKey = sodium
      .from_hex(entropyHex)
      .subarray(0, sodium.crypto_secretbox_KEYBYTES);
    const nonce = sodium.from_hex(array[1]);
    const cipherMessage = sodium.from_base64(array[2]);
    return sodium.crypto_secretbox_open_easy(cipherMessage, nonce, encKey);
  } catch (e) {
    const errorMsg = e instanceof Error ? e.message : e;
    throw new Error(`Failed to decrypt backup data: ${errorMsg}`);
  }
}

function verifyChecksum(backup: SnapBackup): boolean {
  let { hash: checksum, ...backupWithoutHash } = backup;
  const canonicalJson = canonicalSerialize(backupWithoutHash);
  const hash = bytesToHex(keccak256(canonicalJson));
  if (checksum.startsWith("0x")) {
    checksum = checksum.slice(2);
  }
  return hash.slice(2) === checksum;
}

/**
 * Export private keys from a mnemonic phrase and Snap + App backup data
 * @param mnemonicPhrase Mnemonic phrase of Metamask wallet
 * @param backup Snap + App backup data
 * @returns List of exported private keys
 */
export async function exportKeys(mnemonicPhrase: string, backup: SnapBackup) {
  mnemonicPhrase = mnemonicPhrase.trim();
  if (!verifyChecksum(backup)) {
    throw new Error("Invalid backup data, checksum mismatch");
  }

  let privateKeys: ExportedKey[] = [];
  for (let walletBackup of backup.wallet) {
    // Get the encryption salt
    const salt = walletBackup.remote.split(".")[0];

    // Derive the entropy from the mnemonic phrase
    const entropyHex = await getEntropy(
      mnemonicPhrase,
      SNAP_ID,
      hexToBytes(salt).toString(),
    );

    // Decrypt the snap backup data
    const data = await decSnapBackup(entropyHex, walletBackup.remote);

    // Decode the Snap keyshare data
    const dec = new TextDecoder();
    const a = dec.decode(data);
    const snapKeyshare = JSON.parse(a);

    // Get the Snap private key
    const x1Hex: string = snapKeyshare.keyShareData.x1;
    const x1 = hexToBigInt(x1Hex);

    // Decode the app backup data
    const app = sodium.from_base64(
      walletBackup.keyshare,
      sodium.base64_variants.ORIGINAL,
    );
    const appData = JSON.parse(dec.decode(app));

    // Get the app private key
    const x2 = hexToBigInt(appData.x2.scalar);

    // Recover the private key
    const privateKey = (x1 * x2) % secp256k1.curve.n;

    // Check that the recovered private key matches the address
    const publicKey = secp256k1.getPublicKey(bigIntToBytes(privateKey), false);
    const address = bytesToHex(keccak256(publicKey.slice(1))).substring(26);
    console.assert(
      "0x" + address === walletBackup.address,
      "Recovered private key, but there's an address mismatch. Keyshare pair is invalid. This is a bug.",
    );

    privateKeys.push({
      address: walletBackup.address,
      privateKey: bigIntToHex(privateKey),
    });
  }

  return privateKeys;
}
