# protect-password

`protect-password` is a lightweight, dependency-free JavaScript library for securely hashing passwords and verifying password hashes using PBKDF2 with sha512. It provides a secure way to protect passwords and uses timing-safe comparison to prevent timing attacks.

## Why You Need This

When building secure applications, password security is critical. Hashing passwords ensures that even if the password database is compromised, the plaintext passwords are not exposed.

This library helps you:

- Securely hash passwords using PBKDF2 (Password-Based Key Derivation Function 2) with sha512.
- Safely verify passwords using constant-time comparisons to avoid timing attacks.

## Security and Performance

This package uses the PBKDF2 algorithm with a sha512 hash, which is recommended by NIST (National Institute of Standards and Technology). PBKDF2 is a password-stretching mechanism that adds computational effort, making brute-force attacks much harder.

`protect-password` defaults to 1,000,000 iterations, which balances security and performance. You can modify the iteration count based on your specific needs, but we recommend sticking with our default, which will increase with future releases.

## Future Enhancements

In the future, we plan to add options for algorithms such as:

- **scrypt**: A memory-hard password hashing function.
- **Argon2**: The winner of the Password Hashing Competition, designed for security and performance.

> **Note:** Argon2 may require using a third-party library until Node.js adds built-in support.

## How to Use

### Install the package

```bash
npm install protect-password
```

If you are using TypeScript, install the type definitions as well:

```bash
npm install protect-password-types
```

### Protect a Password

```javascript
const { protect } = require("protect-password");

const password = "mysecretpassword";
const protectedHash = protect(password);
console.log(protectedHash); // Output: pbkdf2_sha512$1000000$salt$hash
```

### Verify a Password

```javascript
const { verify } = require("protect-password");

const password = "mysecretpassword";
const storedHash = "pbkdf2_sha512$1000000$salt$hash";

const isValid = verify(password, storedHash);
console.log(isValid); // Output: true or false
```

### Customizing Iterations

By default, `protect-password` uses 1,000,000 iterations. You can modify this based on your security requirements:

```javascript
const { protect } = require("protect-password");

const options = { iterations: 500_000 };
const protectedHash = protect("mysecretpassword", options);
```

However, we recommend using the default as it offers robust security. Future releases will increment the default iteration count as computing power increases.

## License

This project is licensed under the MIT License. Feel free to fork it, extend it, and use it in your projects.
