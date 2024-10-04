const {
  protect,
  verify,
  hashPassword,
  encodePassword,
  decodePassword,
} = require(".");

describe("Password Utility Functions", () => {
  const testPassword = "MySecurePassword123!";

  test("hashPassword should generate a hash and salt", () => {
    const { salt, hash } = hashPassword(testPassword);
    expect(salt).toBeDefined();
    expect(hash).toBeDefined();
    expect(typeof salt).toBe("string");
    expect(typeof hash).toBe("string");
  });

  test("encodePassword should encode a password in the expected format", () => {
    const encoded = encodePassword(testPassword);
    const parts = encoded.split("$");
    expect(parts.length).toBe(4);
    expect(parts[0]).toBe("pbkdf2_sha512");
    expect(parseInt(parts[1])).toBeGreaterThan(0);
    expect(parts[2].length).toBeGreaterThan(0);
    expect(parts[3].length).toBeGreaterThan(0);
  });

  test("decodePassword should decode the encoded password", () => {
    const encoded = encodePassword(testPassword);
    const decoded = decodePassword(encoded);
    expect(decoded.algorithm).toBe("pbkdf2_sha512");
    expect(decoded.iterations).toBeGreaterThan(0);
    expect(decoded.salt.length).toBeGreaterThan(0);
    expect(decoded.hash.length).toBeGreaterThan(0);
  });

  test("protect should return a formatted hash", () => {
    const storedHash = protect(testPassword);
    const parts = storedHash.split("$");
    expect(parts.length).toBe(4);
  });

  test("verify should return true for correct password", () => {
    const storedHash = protect(testPassword);
    const isValid = verify(testPassword, storedHash);
    expect(isValid).toBe(true);
  });

  test("verify should return false for incorrect password", () => {
    const storedHash = protect(testPassword);
    const isValid = verify("WrongPassword", storedHash);
    expect(isValid).toBe(false);
  });

  test("verify should throw an error for invalid hash format", () => {
    expect(() => verify(testPassword, "invalid$hash")).toThrowError(
      "Invalid encoded password format"
    );
  });
});
