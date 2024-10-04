const crypto = require("crypto");

// Default security options
const defaultOptions = {
  algorithm: "pbkdf2",
  iterations: 1_000_000, // Secure default: 1 million iterations
  saltLength: 16, // 16 bytes (128 bits) for the salt (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
  outputLength: 64, // 64 bytes (512 bits) for hash length
  digest: "sha512",
};

/**
 * Hashes a password using the PBKDF2 algorithm with sha512.
 * @param {string} password - The plain text password to hash.
 * @param {string} [salt] - The salt to use for hashing (optional).
 * @param {object} [options] - Options to override the default algorithm, iterations, and salt length.
 * @returns {object} - An object containing the salt and the base64 encoded hash.
 */
function hashPassword(password, salt = null, options = {}) {
  if (!password) throw new Error("Password is required");

  const { algorithm, iterations, saltLength, outputLength, digest } = {
    ...defaultOptions,
    ...options,
  };
  salt = salt || crypto.randomBytes(saltLength).toString("base64");

  const hash = crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    outputLength,
    digest
  );
  const encodedHash = hash.toString("base64");

  return { salt, hash: encodedHash };
}

/**
 * Encodes a password hash into the agreed format: algorithm_digest$iterations$salt$hash.
 * @param {string} password - The plain text password to encode.
 * @param {object} [options] - Options to override the default algorithm, iterations, and salt length.
 * @returns {string} - The encoded password string including the algorithm, iterations, salt, and hash.
 */
function encodePassword(password, options = {}) {
  const { algorithm, iterations, digest } = { ...defaultOptions, ...options };
  const { salt, hash } = hashPassword(password, null, options);

  // Format: algorithm_digest$iterations$salt$hash
  return `${algorithm}_${digest}$${iterations}$${salt}$${hash}`;
}

/**
 * Decodes an encoded password string into its components: algorithm, iterations, salt, and hash.
 * @param {string} encoded - The encoded password string.
 * @returns {object} - An object containing the algorithm, iterations, salt, and hash.
 */
function decodePassword(encoded) {
  const [algorithm, iterations, salt, hash] = encoded.split("$");
  if (!algorithm || !iterations || !salt || !hash) {
    throw new Error("Invalid encoded password format");
  }

  return {
    algorithm,
    iterations: parseInt(iterations, 10),
    salt,
    hash,
  };
}

/**
 * Protects a password by encoding it for storage.
 * @param {string} password - The plain text password to protect.
 * @param {object} [options] - Options to override the default algorithm, iterations, and salt length.
 * @returns {string} - The encoded password string including the algorithm, iterations, salt, and hash.
 */
function protect(password, options = {}) {
  return encodePassword(password, options);
}

/**
 * Verifies a password against the given encoded password.
 * @param {string} inputPassword - The plain text password to verify.
 * @param {string} storedHash - The stored encoded password.
 * @returns {boolean} - Whether the password matches the stored hash.
 */
function verify(inputPassword, storedHash) {
  const decoded = decodePassword(storedHash);
  const { salt, iterations } = decoded;

  const { hash: newHash } = hashPassword(inputPassword, salt, { iterations });

  return crypto.timingSafeEqual(
    Buffer.from(decoded.hash),
    Buffer.from(newHash)
  );
}

module.exports = {
  protect,
  verify,
  hashPassword,
  encodePassword,
  decodePassword,
};
