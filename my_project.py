import time
import statistics
import os
import csv
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, ec, x25519, mlkem, ed25519, mldsa
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, AESGCMSIV, ChaCha20Poly1305
)

def measure(operation, runs=101):
    times = []

    for run in range(runs):
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()

        elapsed = end - start
        times.append(elapsed)

    measured = times[1:]

    median = statistics.median(measured)
    quartiles = statistics.quantiles(measured, n=4)
    iqr = quartiles[2] - quartiles[0]

    return times, median, iqr

def save_measurements(writer, part, algorithm, operation, times):
    for run, nanoseconds in enumerate(times):
        writer.writerow([
            part,
            algorithm,
            operation,
            0,
            run,
            nanoseconds
        ])

def rsa_keygen(key_size):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def rsa_encapsulate(public_key):
    secret = os.urandom(32)

    ciphertext = public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return secret, ciphertext

def rsa_decapsulate(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def benchmark_rsa(key_size, writer):
    algorithm = f"RSA-OAEP-{key_size}"

    print(f"\n{algorithm} Benchmark")

    private_key = rsa_keygen(key_size)
    public_key = private_key.public_key()

    secret, ciphertext = rsa_encapsulate(public_key)
    recovered = rsa_decapsulate(private_key, ciphertext)

    assert secret == recovered
    print("Encapsulation and decapsulation: OK")

    operations = [
        ("keygen", lambda: rsa_keygen(key_size), 21),
        ("encapsulate", lambda: rsa_encapsulate(public_key), 101),
        ("decapsulate", lambda: rsa_decapsulate(private_key, ciphertext), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "kem", algorithm, operation_name, times
        )

def ecdh_keygen(curve):
    return ec.generate_private_key(curve)


def ecdh_encapsulate(public_key, curve):
    ephemeral_private = ec.generate_private_key(curve)

    secret = ephemeral_private.exchange(
        ec.ECDH(),
        public_key
    )

    ciphertext = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return secret, ciphertext

def ecdh_decapsulate(private_key, ciphertext):
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        private_key.curve,
        ciphertext
    )

    return private_key.exchange(
        ec.ECDH(),
        ephemeral_public
    )

def benchmark_ecdh(algorithm, curve, writer):
    print(f"\n{algorithm} Benchmark")

    private_key = ecdh_keygen(curve)
    public_key = private_key.public_key()

    secret, ciphertext = ecdh_encapsulate(public_key, curve)
    recovered = ecdh_decapsulate(private_key, ciphertext)

    assert secret == recovered
    print("Encapsulation and decapsulation: OK")

    operations = [
        ("keygen", lambda: ecdh_keygen(curve), 101),
        ("encapsulate", lambda: ecdh_encapsulate(public_key, curve), 101),
        ("decapsulate", lambda: ecdh_decapsulate(private_key, ciphertext), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "kem", algorithm, operation_name, times
        )

def x25519_keygen():
    return x25519.X25519PrivateKey.generate()


def x25519_encapsulate(public_key):
    ephemeral_private = x25519_keygen()

    secret = ephemeral_private.exchange(public_key)

    ciphertext = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return secret, ciphertext


def x25519_decapsulate(private_key, ciphertext):
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
        ciphertext
    )

    return private_key.exchange(ephemeral_public)

def benchmark_x25519(writer):
    algorithm = "X25519"

    print(f"\n{algorithm} Benchmark")

    private_key = x25519_keygen()
    public_key = private_key.public_key()

    secret, ciphertext = x25519_encapsulate(public_key)
    recovered = x25519_decapsulate(private_key, ciphertext)

    assert secret == recovered
    print("Encapsulation and decapsulation: OK")

    operations = [
        ("keygen", x25519_keygen, 101),
        ("encapsulate", lambda: x25519_encapsulate(public_key), 101),
        ("decapsulate", lambda: x25519_decapsulate(private_key, ciphertext), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "kem", algorithm, operation_name, times
        )

def benchmark_mlkem(algorithm, key_class, writer):
    print(f"\n{algorithm} Benchmark")

    private_key = key_class.generate()
    public_key = private_key.public_key()

    secret, ciphertext = public_key.encapsulate()
    recovered = private_key.decapsulate(ciphertext)

    assert secret == recovered
    print("Encapsulation and decapsulation: OK")

    operations = [
        ("keygen", key_class.generate, 101),
        ("encapsulate", public_key.encapsulate, 101),
        ("decapsulate", lambda: private_key.decapsulate(ciphertext), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "kem", algorithm, operation_name, times
        )

def rsa_sign(private_key, message):
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH
    )

    return private_key.sign(
        message,
        pss,
        hashes.SHA256()
    )


def rsa_verify(public_key, signature, message):
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH
    )

    public_key.verify(
        signature,
        message,
        pss,
        hashes.SHA256()
    )

def benchmark_rsa_pss(key_size, message, writer):
    algorithm = f"RSA-PSS-{key_size}"

    print(f"\n{algorithm} Benchmark")

    private_key = rsa_keygen(key_size)
    public_key = private_key.public_key()

    signature = rsa_sign(private_key, message)

    rsa_verify(public_key, signature, message)
    print("Sign and verify: OK")

    operations = [
        ("keygen", lambda: rsa_keygen(key_size), 21),
        ("sign", lambda: rsa_sign(private_key, message), 101),
        ("verify", lambda: rsa_verify(public_key, signature, message), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "signature", algorithm, operation_name, times
        )

def ecdsa_sign(private_key, message, hash_algorithm):
    return private_key.sign(
        message,
        ec.ECDSA(hash_algorithm)
    )


def ecdsa_verify(public_key, signature, message, hash_algorithm):
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hash_algorithm)
    )

def benchmark_ecdsa(algorithm, curve, hash_algorithm, message, writer):
    print(f"\n{algorithm} Benchmark")

    private_key = ecdh_keygen(curve)
    public_key = private_key.public_key()

    signature = ecdsa_sign(private_key, message, hash_algorithm)

    ecdsa_verify(public_key, signature, message, hash_algorithm)
    print("Sign and verify: OK")

    operations = [
        ("keygen", lambda: ecdh_keygen(curve), 101),
        ("sign", lambda: ecdsa_sign(private_key, message, hash_algorithm), 101),
        ("verify", lambda: ecdsa_verify(public_key, signature, message, hash_algorithm), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "signature", algorithm, operation_name, times
        )

def benchmark_modern_signature(algorithm, key_class, message, writer):
    print(f"\n{algorithm} Benchmark")

    private_key = key_class.generate()
    public_key = private_key.public_key()

    signature = private_key.sign(message)
    public_key.verify(signature, message)

    print("Sign and verify: OK")

    operations = [
        ("keygen", key_class.generate, 101),
        ("sign", lambda: private_key.sign(message), 101),
        ("verify", lambda: public_key.verify(signature, message), 101)
    ]

    for operation_name, operation, runs in operations:
        times, median, iqr = measure(operation, runs)

        print(f"\n{operation_name}:")
        print("Runs:", len(times))
        print("Median (ms):", median / 1_000_000)
        print("IQR (ms):", iqr / 1_000_000)

        save_measurements(
            writer, "signature", algorithm, operation_name, times
        )    

def save_aead_measurements(writer, algorithm, operation, message_size, times):
    for run, nanoseconds in enumerate(times):
        writer.writerow([
            "aead",
            algorithm,
            operation,
            message_size,
            run,
            nanoseconds
        ])


def benchmark_aead(algorithm, cipher_class, key_size, message_size, writer):
    print(f"\n{algorithm} - {message_size} bytes")

    key = os.urandom(key_size)
    message = os.urandom(message_size)

    cipher = cipher_class(key)

    # Prepare ciphertext for decryption
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, message, None)

    recovered = cipher.decrypt(nonce, ciphertext, None)
    assert recovered == message

    print("Encryption and decryption: OK")

    # Encryption: fresh nonce for every run, generated outside timing
    encryption_times = []

    for run in range(101):
        nonce = os.urandom(12)

        start = time.perf_counter_ns()
        cipher.encrypt(nonce, message, None)
        end = time.perf_counter_ns()

        encryption_times.append(end - start)

    measured = encryption_times[1:]
    median = statistics.median(measured)
    quartiles = statistics.quantiles(measured, n=4)
    iqr = quartiles[2] - quartiles[0]

    print("\nencrypt:")
    print("Runs:", len(encryption_times))
    print("Median (ms):", median / 1_000_000)
    print("IQR (ms):", iqr / 1_000_000)

    save_aead_measurements(
        writer, algorithm, "encrypt", message_size, encryption_times
    )

    fixed_nonce = os.urandom(12)
    fixed_ciphertext = cipher.encrypt(fixed_nonce, message, None)

    # Decryption: same ciphertext for all runs
    decryption_times, median, iqr = measure(
        lambda: cipher.decrypt(
            fixed_nonce, fixed_ciphertext, None
        )
    )

    print("\ndecrypt:")
    print("Runs:", len(decryption_times))
    print("Median (ms):", median / 1_000_000)
    print("IQR (ms):", iqr / 1_000_000)

    save_aead_measurements(
        writer, algorithm, "decrypt", message_size, decryption_times
    ) 

message = os.urandom(1024)

if len(sys.argv) != 2:
    print("Usage: python my_project.py <output_directory>")
    sys.exit(1)

output_dir = Path(sys.argv[1])
output_dir.mkdir(parents=True, exist_ok=True)

output_file = output_dir / "raw.csv"

with open(output_file, "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "part",
        "algorithm",
        "operation",
        "message_bytes",
        "run",
        "nanoseconds"
    ])

    benchmark_rsa(3072, writer)
    benchmark_rsa(7680, writer)

    benchmark_ecdh("ECDH-P-256", ec.SECP256R1(), writer)
    benchmark_ecdh("ECDH-P-384", ec.SECP384R1(), writer)
    benchmark_ecdh("ECDH-P-521", ec.SECP521R1(), writer)

    benchmark_x25519(writer)

    benchmark_mlkem("ML-KEM-768", mlkem.MLKEM768PrivateKey, writer)
    benchmark_mlkem("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, writer)
    benchmark_rsa_pss(3072, message, writer)
    benchmark_rsa_pss(7680, message, writer)

    benchmark_ecdsa(
        "ECDSA-P-256", ec.SECP256R1(), hashes.SHA256(), message, writer
    )

    benchmark_ecdsa(
        "ECDSA-P-384", ec.SECP384R1(), hashes.SHA384(), message, writer
    )

    benchmark_ecdsa(
        "ECDSA-P-521", ec.SECP521R1(), hashes.SHA512(), message, writer
    )

    benchmark_modern_signature(
        "Ed25519", ed25519.Ed25519PrivateKey, message, writer
    )

    benchmark_modern_signature(
        "ML-DSA-44", mldsa.MLDSA44PrivateKey, message, writer
    )

    benchmark_modern_signature(
        "ML-DSA-65", mldsa.MLDSA65PrivateKey, message, writer
    )

    benchmark_modern_signature(
        "ML-DSA-87", mldsa.MLDSA87PrivateKey, message, writer
    )

    message_sizes = [64, 1024, 16384, 1048576]

    aead_algorithms = [
        ("AES-128-GCM", AESGCM, 16),
        ("AES-256-GCM", AESGCM, 32),
        ("ChaCha20-Poly1305", ChaCha20Poly1305, 32),
        ("AES-256-GCM-SIV", AESGCMSIV, 32)
    ]

    for algorithm, cipher_class, key_size in aead_algorithms:
        for message_size in message_sizes:
            benchmark_aead(
                algorithm, cipher_class, key_size, message_size, writer
            )

print("\nResults saved to:", output_file)