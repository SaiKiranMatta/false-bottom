import { randomBytes } from "crypto";

// Global variables for field prime, secret key, and ciphertext
const p = 18446744073709551629n; // Large fixed prime for field
let r: bigint[] = [];
let c: bigint[] = [];

// Helper function to generate a random element in the field
function randomFieldElement(): bigint {
    return randomBigIntBetween(1n, p);
}

// Generates a random bigint between a min and max value
function randomBigIntBetween(min: bigint, max: bigint): bigint {
    const range = max - min;
    const byteLength = Math.ceil(range.toString(2).length / 8);
    let randomBytesBuffer;

    do {
        randomBytesBuffer = randomBytes(byteLength);
        const randomBigInt = BigInt(`0x${randomBytesBuffer.toString("hex")}`);
        const adjustedValue = min + (randomBigInt % range);
        if (adjustedValue < max) {
            return adjustedValue;
        }
    } while (true);
}

// Function to encrypt a block of the message and add it to the existing ciphertext
function encryptBlock(
    block: string,
    k: number,
    keyLength?: number
): [bigint[], [number, bigint][]] {
    // Initialize key base and ciphertext if not already initialized
    if (r.length === 0 || c.length === 0) {
        // Use specified key length or default to k if not provided
        const length = keyLength && keyLength <= k ? keyLength : k;
        r = Array.from({ length }, () => randomFieldElement());
        c = Array.from({ length }, () => randomFieldElement());
    }

    // Choose random number of indices to work with
    const ni = Math.min(Math.floor(Math.random() * k) + 2, r.length);
    const indices = sampleIndices(ni - 1, c.length); // sample from current ciphertext length
    const alphas = indices.map((i) => c[i]);
    const rhoIndices = sampleIndices(ni, r.length);
    const rs = rhoIndices.map((i) => r[i]);

    // Calculate sum and encrypt the message
    let sum = 0n;
    for (let i = 0; i < ni - 1; i++) {
        sum += alphas[i] * rs[i];
    }

    const messageBigInt = stringToBigInt(block);
    const lastAlpha = ((messageBigInt - sum) * modInverse(rs[ni - 1], p)) % p;

    // Update ciphertext with the new value
    c.push(lastAlpha);
    const newCiphertextIndex = c.length - 1;

    // Create secret key for this block with actual r values
    const secretKey: [number, bigint][] = [
        ...indices.map((j, i) => [j, rs[i]] as [number, bigint]), // Store actual r values
        [newCiphertextIndex, rs[ni - 1]], // Store actual r value
    ];

    return [c, secretKey];
}

// Function to encrypt a single message and add it to the existing ciphertext
export function addToCiphertext(
    existingCiphertext: bigint[],
    newText: string,
    blockSize: number = 8, // Default block size
    k: number = 5, // Default k
    keyLength?: number // Optional key length
): { updatedCiphertext: bigint[]; newSecretKey: [number, bigint][] } {
    // Input validation
    if (blockSize <= 0 || blockSize > 8) {
        throw new Error(
            "Block size must be greater than 0 and less than or equal to 8."
        );
    }
    if (k <= 0) {
        throw new Error("k must be greater than 0.");
    }
    if (keyLength && (keyLength <= 0 || keyLength > k)) {
        throw new Error(
            "Key length must be greater than 0 and less than or equal to k."
        );
    }
    if (newText.length === 0) {
        throw new Error("New text must not be empty.");
    }

    // Change return type
    const blocks = chunkMessage(newText, blockSize);
    let finalCiphertext = [...existingCiphertext]; // Start with the existing ciphertext
    let finalSecretKey: [number, bigint][] = [];
    const offset = finalCiphertext.length; // Calculate the offset for new indices

    // Encrypt each block and add it to the ciphertext
    blocks.forEach((block) => {
        const [ciphertext, secretKey] = encryptBlock(block, k, keyLength);
        finalCiphertext.push(...ciphertext);

        // Remap secret keys with the offset
        const remappedSecretKey = secretKey.map(
            ([cIndex, rValue]) => [cIndex + offset, rValue] as [number, bigint]
        );
        finalSecretKey.push(...remappedSecretKey);
    });

    return { updatedCiphertext: finalCiphertext, newSecretKey: finalSecretKey };
}

// Function to decrypt the ciphertext using the secret key
export function decryptMessage(
    ciphertext: bigint[],
    secretKey: [number, bigint][]
): string {
    // Input validation
    if (ciphertext.length === 0) {
        throw new Error("Ciphertext must not be empty.");
    }
    if (secretKey.length === 0) {
        throw new Error("Secret key must not be empty.");
    }

    let result = 0n;
    for (const [cIndex, rValue] of secretKey) {
        // Validate index
        if (cIndex < 0 || cIndex >= ciphertext.length) {
            throw new Error(`Invalid ciphertext index: ${cIndex}`);
        }
        result += ciphertext[cIndex] * rValue; // Use rValue instead of rIndex
    }
    const messageBigint = ((result % p) + p) % p;
    return bigintToString(messageBigint);
}

// Utility to split the message into blocks of the specified size
function chunkMessage(message: string, size: number): string[] {
    const chunks: string[] = [];
    for (let i = 0; i < message.length; i += size) {
        chunks.push(message.slice(i, i + size));
    }
    return chunks;
}

// Randomly sample indices
function sampleIndices(count: number, max: number): number[] {
    const indices = new Set<number>();
    while (indices.size < count) {
        indices.add(Math.floor(Math.random() * max));
    }
    return Array.from(indices);
}

// Calculate modular inverse
function modInverse(a: bigint, m: bigint): bigint {
    let [oldR, r] = [a, m];
    let [oldS, s] = [1n, 0n];
    let quotient: bigint, temp: bigint;

    while (r !== 0n) {
        quotient = oldR / r;
        temp = r;
        r = oldR - quotient * r;
        oldR = temp;
        temp = s;
        s = oldS - quotient * s;
        oldS = temp;
    }

    if (oldR > 1n) throw new Error("Not invertible");
    if (oldS < 0n) oldS += m;
    return oldS;
}

// Convert bigint to string
function bigintToString(bigInt: bigint): string {
    const hexString = bigInt.toString(16);
    const buffer = Buffer.from(hexString, "hex");
    return buffer.toString("utf8");
}

// Convert string to bigint
function stringToBigInt(str: string): bigint {
    return BigInt("0x" + Buffer.from(str, "utf8").toString("hex"));
}
