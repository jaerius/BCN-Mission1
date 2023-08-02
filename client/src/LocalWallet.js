import * as secp from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { hexToBytes, toHex } from "ethereum-cryptography/utils";

/**
 * Local wallet.
 * Simulate a MetaMask-like wallet which stores private keys safely,
 * and gives access to public key/address.
 * Keys are store in hexadecimal format.
 */

// List of account keys in hexa format without the '0x'
const ACCOUNT_KEYS = new Map([
  [
    "bob",
    {
      private:
        "c47e66a613e6b7ce2229f78d1acb5475170b4bf23ed02f64af4bf25baae5bdfc",
      public:
        "04e87316003badc30d885f09a020d48f8567df003c7e5f43418884ac8366e5d5c17e02af87ec5c217da9c52ccc8c76a470c80d881af93414f58740847133a88393",
    },
  ],
  [
    "alice",
    {
      private:
        "c16e2ac3ddd06f02818aededa7598840bf3ed697ea098fa8d7fe0337d750e4e1",
      public:
        "04dbf6195484429fe379ea5c921231303f9722bc8da7cb4236d3b6cf5ace525178d7eed400fd2b93e3741fce2aa9189d21520f1651f29679800189fbabdf350afb",
    },
  ],
  [
    "charles",
    {
      private:
        "cebf6cd6f033901a212e95cd6f4a23a2a7a8299b0d2429f8e838b5b2d1ee336c",
      public:
        "041a29c5e0e72ab1461d4b15d6385b3ce464c7ec737cce113f378ae767af903a309982b6da43786470adddb4d5946f4f3fbcab9575e4e830984920b4f2faa1d20d",
    },
  ],
]);

// user names derived from the list of accounts
const USERS = Array.from(ACCOUNT_KEYS.keys());

/**
 * Hash a message using KECCAK-256
 * @param message the message to hash.
 * @returns the hash of the message.
 */
const hashMessage = (message) => keccak256(Uint8Array.from(message));

/**
 * Get the user public key.
 * @param user the user
 * @returns the public key as a Uint8Array.
 */
const getPublicKey = (user) => {
  if (!user) return null;
  return hexToBytes(ACCOUNT_KEYS.get(user).public);
};

/**
 * Get the user private key.
 * @param user the user.
 * @returns the private key as a Uint8Array.
 */
const getPrivateKey = (user) => {
  if (!user) return null;
  return hexToBytes(ACCOUNT_KEYS.get(user).private);
};

/**
 * Derive the address from the public key of an user.
 * @param user the user.
 * @returns the user address as a hexa string.
 */
const getAddress = (user) => {
  if (!user) return null;
  const pubKey = getPublicKey(user);
  const hash = keccak256(pubKey.slice(1));
  return toHex(hash.slice(-20)).toUpperCase();
};

/**
 * Get the public key of an user in hexa format.
 * @param user the user.
 * @returns the public key.
 */
const getHexPubKey = (user) => {
  if (!user) return null;
  return toHex(getPublicKey(user)).toUpperCase();
};

/**
 * Sign a message.
 * @param username name of the user account.
 * @param message message to sign
 * @returns the signature in hexa format with the recovery bit as the first byte.
 */
const sign = async (username, message) => {
  const privateKey = getPrivateKey(username);
  const hash = hashMessage(message);

  const [signature, recoveryBit] = await secp.sign(hash, privateKey, {
    recovered: true,
  });
  const fullSignature = new Uint8Array([recoveryBit, ...signature]);
  return toHex(fullSignature);
};

const wallet = {
  USERS,
  sign,
  getAddress,
  getHexPubKey,
};
export default wallet;
