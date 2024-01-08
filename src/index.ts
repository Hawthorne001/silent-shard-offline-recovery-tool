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
  salt = ""
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
  snapBackup: string
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
      hexToBytes(salt).toString()
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
      sodium.base64_variants.ORIGINAL
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
      "Recovered private key, but there's an address mismatch. Keyshare pair is invalid. This is a bug."
    );

    privateKeys.push({
      address: walletBackup.address,
      privateKey: bigIntToHex(privateKey),
    });
  }

  return privateKeys;
}

// const phrase =
//   "replace frog rebuild copy unique pulp wait hat husband this smile cable";

// const backup = {
//   time: "2024-01-08T14:46:29.319933Z",
//   version: 1,
//   wallet: [
//     {
//       address: "0x878bccf7fbc26fd6dae0001eebb7d892be60e7bd",
//       keyshare:
//         "eyJ4MiI6eyJjdXJ2ZSI6InNlY3AyNTZrMSIsInNjYWxhciI6ImU5N2ZhM2FlMzIwOTE5ZWExYzRmNjRjNTYxNjYxNDQ2YWNlZTgxNTBmYzU2ZDAxNTA3ZmJlMDMxZjc2NGRiODgifSwicm9vdF9wdWJsaWNfa2V5Ijp7ImN1cnZlIjoic2VjcDI1NmsxIiwicG9pbnQiOiIwM2I4ZTQ3YWJiYWQyYWI4YzhjMjM1MWM3YTZmMzFmYzJjMDYzYWQyZTJjNzE3YWFmZjQ0MDlhZTk1N2M2Y2YyNGIifSwiY19rZXlfeDEiOiI3MjIwZTMxZmRmYTExZGMxNDJmOTIzOWU4Y2U5OWVkNmEyMWNjYzE5MzlmMjY0M2JjYWYwOTRkNDI1ZmVlN2I4YzUxYmViZmZmOWJmNWYzMGNhMTlkM2I1MWZmZTQ1ZTU5N2FhM2Y1YjRiOGNmN2NhOGQ2N2E2MGQ0NzU2NTZhZDk1MTgxOWI5NjE4MTU3MDUzN2I4NzE1ZjMxYzM4Mzc0ZGZmZjY5MzUyMzRhYWVhMzBhZDE3OTUzNzI5MGYxZjFjNGM1ZjUxMmZiMWZhOWU3OGViNjBhN2FmYTA4NGI3YmNjZDZhOTU2ZTM1ZTU5ZTFiYjBlMTZmZmUxZjBhNWIwZmFhODVjMmYzZjU0MWZjYjc4NzU2OWYzYzI2MzE5ZjgyZTk2ZTU3NWYzNDkyZWIxZmUzYjYxZTcxMGJlYzE4YTU4NTE4NzQwODZiZGIyM2RlZDNjNjA4MGU2MDU1ZjBmMGM3Zjk2Nzc4MmUxZTYwNzliZmE1YTU3ODIxZjI5ZjAxNmQzM2NjODA5NGI0MWEwZGI5MGEwNWU1ZTJmZTY0ZGIxYWM4ZTg5ZjhmYzQ5Y2Y3OGJiN2ZmOTFiODNkZjFhZGI1MDQwODdhOGNlYTg3YTIxNzgxMTQ4OWI2YzJhYjhlNWUwMmI4MjQ5NzVlYzdlMmI5YzIyMTBjYzliNWMwMTdlMjY3NDZhZjE4MGUxMmMwMzViNWVlN2ZjYjg4NTUyYjQwODVkZWM1MjUwYzU1ODZkMjczYTgzYjM1ZWE4OGRjMjBlOTFjNDNhNjU1ZjEzYmFiNjMyZDFmMzA4YTJhOTk4NGIzNGUzMDViY2U3YTU5Y2UwNjZiZjNiNThhOWRkMTZlODRmMjNkOTdjNmVjMTZhZTM5ZTRiY2RmNmFlNGQ2OTZhMWIzMGQwYjhiNGRkMDJjZDM5ZDUyMGMyYjU1MzhhYWQ3MDIxNDQzYWI0NjQwMzMwOTRkNjRlZGExYjE1MmFiZTNmNjg3N2QyMDY5NWIxZGIzOTgwZjNkOTFjNDc1NDA3YTI4MGQyNjE3YTdiZDdhYzVlYzkyMmMzM2IzMjc3YmEzODZlOTMxODYwN2ExY2QwZGFiNmM1YmI1MzI2YWFkMTZhMWZjYTE4ZGQxMzYwMTU3NjMxZTEwNmZlMTU1NDZmODRiZDhjNjE5Yzg5YWNlYmZiYTliY2E3ZjBkNDY0NjRhNGZmYTdiNGY0MzAyZDQ4YTI1ZjIzMWE5NDM5ZmUxNGMzODFkMzJiMDBhMWU0ZDFiN2RiZmU3MDViZDMzMzk4OTY1NTQxNjQ2ZTQzNjQxZGU0MTE0NDYyMDFhZjU1NTI2NzYzY2RhZWJhZmZmNjgyN2IyODE4NmRhMzJmIiwicGFpbGxpZXJfcHVia2V5Ijp7Im4iOiIyMTcwNTQzNzMzNjQwNjgwMjg1MDAwNzM3MjU5ODM3NDkxMDk3MDUyMDc2NTk4MzY1OTA0NzM1NTYyODMxOTM2Njc2MDUzNTI5NTk5OTAxMzE3ODI3MjQ3MjYyMjU0ODk5MTUzOTAxOTM3NjI3OTkxNjI0NzA4OTM5NjI3NjIyNjQwODYxMzc0OTIyNDk2NjA1NzQ1MzI2NzI3NjU0MjQwMzYwMTIwOTQ4OTk5MTA1Nzk3MzY4MDYxMjcwODY4MDY3ODk5NTE2NzMxNTQ2MTM2MjQ4MDU1MDgwMDg4MDI3MDE0MDk4NTU5NzkzMDY5MzkzNTk3MTgwMzUxOTI1ODE2NzA3Nzk4MDc5OTUyMTQ0MzQxNjIyMDUyOTg1MzcxMjUzMjM5MTM3MjM5NDM0MjQ5MTgzMDY1Njk1NzQ2ODMxODI5MDUyNzMzNTU5Nzc5NzMzOTczNzk2NjExNDAwOTQyMjAyODE5ODc5Nzk0NDIzNDgwOTMzMDI2NTU1OTMxOTIwMjAwODczMjY4MDYxMjI5OTMyODUyMjQ4OTg0MTU3NTk0NDYwODA0NTQ3MTIzMTk2OTQ1Njc2OTQ3MDM3NzQwMTQyMTQ1MDU5OTI2MDYxOTU1MjAwODE5NDI2Mzk3MjkxNzIyNzI4MzYzNTkxNjc0NzgzMjI4NDY2ODk5NDkwOTM1MjgxNjM1MTg2ODU4NDQ3OTM3MTEyMzgzNTcxODgwNTU3MzQ5Njk1Nzc5MzAzMjQ2NjI3NjY5ODEyODYyMzkxMDU0MTQ4NzQ1NDYwODQxODMwOTg2MDk3NzYzNTQ2MjIyNTI2NjQwNyJ9fQ==",
//       remote:
//         "c13902cea22088fac5ed3e8be950cff0a1597ac68d926e7ce7789e463fe42bed.7c2a6b9ed828c8f76566a1410db2487b82e2cd4dc2117e0f.WJER7sFxfaoODCKgTGVnkPcdNRCflz3DVl6ITG0RDhVf0L_Eg5mtHC-Ktp3g9qRN3d8EgkG4V5bPVJLyiwZsETR9rcPF260ClBvE0sHiCect7YEt0SPL1_7Q4eTORV-tTunefYerEEg3JhOVp1h9fpxPGwU6P2Y4klLRd-dyvvG92TIxPH7gNwXmQx0NQ6zjjrIZMgUz3Z1CqSTVwy44yFkJUYjGakZly2RVd_4sDahT6JNn3HivbflceWSw5G1JsO7l6yapmCxnGPNXFv7PRo4GAjp9lAEQ95WTaV2E2eRqdFUddLZCYDl0Mi9hxgoAhW1krzXEN1aUGeXkBHKgkKJtP-HU62TRdWjtqaR8_rGQ34C90Beb2iX1a706ShisXbdJP4fzbKmD6BblX4o032PfbyupWhGm35AJnJAf4LfDZvIxjxx06i_1ZrIEyqBSl9_2gbzs1FC1W2l8bpsvx3M6SyGs8h_bklRbT3xI1s_MPnK2trr4Qrg-Dxq3XrxG8RfPeIT3qW9LfszAE0WrKLmOSA0VSCAzfwdV2djRiKIKgKn4bzpQrwg3XjIaxKCgfYLbjG8ylkz-CGQ1iF807qrG7TvxWjhLVD-Ydm7X-WG01yjwV4QD8BKMe348Qk9Ti2XmcOAp6Y0XaGCzxDS4XLuIqXHpi_RB03RvOYlwRMVLZeMqxJA6QDgdQmqxdw9-UROTCqIwch3xv_-C6j1BTdcbJ9840LFKMl7aqwtM25VfsDzMGbfIpbMRaEZVQ6xB9xhWEsdRIaNR5WstL34qtkKKRHnlFgI77qbAt6PcR6gpYw_Mwv6q1nOHlvFntXq6kAsXByW8GBzzI_Nx7ctmFuujJoWM7YUS7n2woOX4BiZEpByo38ZLaG_hWywD_-V_andGmWrzouldJuNkda88PruAwGqZl5PnkdhJqsmkGhr3UWhXqbbDKn6bXGveDKkdc6cKKgvLRVYsf6TCZbtETvUdLZBFfzLSf3qsV5l-V4C_MmTYbCKngceKayyHpFKQ4qZxcmK2UqK-RDSco8ZQWToaIGaKt-62-kSiW3Q3OLDOzM2fwSuF9_EI0d-BvXs4fXvq0GutYbvTkEQy2Oc6hnJdYYSp70mBJ8Gw60FDG8r5xh6YyBALLp0e8UNL0ql0Pu36xCQzBBmUBaJ5TI4-wbEebGNQpTr6o4J9uWJjJabuxSc9rgzQK2pK6NGvjZSxjjEyn6_hYD-SK8L2Ci5KhB41OZ894uW5f7eEcOmpF4OtOT0YiygqA__2XbdiE4Jsm0tKastKyHQPGuJos6AoElJgX5SW3nmCm0VCc5vftYrUsfGG4WWbU8x2SgNquLlIFo_gWipYtgPRpaN7cBY7xmfLBy9r862uugYP7yVU-vdl485e3UaCjug0osEPGW_fXyQsLH_PQHW42WQN8Ef6FAlZxHFtGdPMGjrS7VfBe93OvViXOz7NbR5TexGG04Kg0J2ONl4-YtqGly25oUL8ILlPEWtl5NE3buBWt_ahMZGzSetAOIko7GdM-h54Bjdb_b-BmHdhyQ",
//     },
//   ],
//   hash: "d6ee65f3e085e1f7fb697d7b172450bab5d49de1817e04dacad2f8c4025139c5",
// };

// exportKeys(phrase, backup).then((keys) => console.log(keys));
