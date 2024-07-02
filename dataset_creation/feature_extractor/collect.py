#!/usr/bin/env python
import csv
import os
import itertools
import math
import numpy as np
import pathlib
from scipy.stats import norm
from collections import Counter

HEXTEXT_DIR = os.environ.get("HEXTEXT_DIR")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE")

OPENSSL_VERSION = os.environ.get("OPENSSL_VERSION")
MBEDTLS_VERSION = os.environ.get("MBEDTLS_VERSION")
WOLFSSL_VERSION = os.environ.get("WOLFSSL_VERSION")
FAKETLS_VERSION = os.environ.get("FAKETLS_VERSION")

CIPHER_SUITES = {
    # IANA Asigned name: (ID, Available version, Key-exchange algorithm, Authentication algorithm, Encryption algorithm(AEAD algorithm in TLS1.3), HMAC algorithm, Hash algorithm used with HKDF(TLS1.3 only))
    # ---- TLS 1.3 ----
    "TLS_AES_128_GCM_SHA256": (
        0x1301,
        "1.3",
        "-",
        "-",
        "AES-128-GCM",
        "-",
        "SHA256",
    ),  # 0x1301, RFC8446
    "TLS_AES_256_GCM_SHA384": (
        0x1302,
        "1.3",
        "-",
        "-",
        "AES-256-GCM",
        "-",
        "SHA384",
    ),  # 0x1302, RFC8446
    "TLS_CHACHA20_POLY1305_SHA256": (
        0x1303,
        "1.3",
        "-",
        "-",
        "CHACHA20-POLY1305",
        "-",
        "SHA256",
    ),  # 0x1303, RFC8446
    "TLS_AES_128_CCM_SHA256": (
        0x1304,
        "1.3",
        "-",
        "-",
        "AES-128-CCM",
        "-",
        "SHA256",
    ),  # 0x1304, RFC8446
    "TLS_AES_128_CCM_8_SHA256": (
        0x1305,
        "1.3",
        "-",
        "-",
        "AES-128-CCM-8",
        "-",
        "SHA256",
    ),  # 0x1305, RFC8446
    "TLS_SHA256_SHA256": (
        0xC0B4,
        "1.3",
        "-",
        "SHA256",
        "NO-ENCRYPTION",
        "SHA256",
        "-",
    ),  # 0xc0b4, RFC9150
    "TLS_SHA384_SHA384": (
        0xC0B5,
        "1.3",
        "-",
        "SHA384",
        "NO-ENCRYPTION",
        "SHA384",
        "-",
    ),  # 0xc0b5, RFC9150
    # ---- TLS 1.2 ----
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA": (
        0xC006,
        "1.2",
        "ECDHE",
        "ECDSA",
        "NO-ENCRYPTION",
        "SHA",
        "-",
    ),  # 0xc006, RFC8422
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": (
        0xC007,
        "1.2",
        "ECDHE",
        "ECDSA",
        "RC4-128",
        "SHA",
        "-",
    ),  # 0xc007, RFC8422/RFC6347
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": (
        0xC008,
        "1.2",
        "ECDHE",
        "ECDSA",
        "3DES-EDE-CBC",
        "SHA",
        "-",
    ),  # 0xc008, RFC8422
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": (
        0xC009,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-128-CBC",
        "SHA",
        "-",
    ),  # 0xc009, RFC8422
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": (
        0xC00A,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-256-CBC",
        "SHA",
        "-",
    ),  # 0xc00a, RFC8422
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": (
        0xC023,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-128-CBC",
        "SHA256",
        "-",
    ),  # 0xc023, RFC5289
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": (
        0xC024,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-256-CBC",
        "SHA384",
        "-",
    ),  # 0xc024, RFC5289
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": (
        0xC02B,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-128-GCM",
        "SHA256",
        "-",
    ),  # 0xc02b, RFC5289
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": (
        0xC02C,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-256-GCM",
        "SHA384",
        "-",
    ),  # 0xc02c, RFC5289
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": (
        0xC072,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CAMELLIA-128-CBC",
        "SHA256",
        "-",
    ),  # 0xc072, RFC6367
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": (
        0xC073,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CAMELLIA-256-CBC",
        "SHA384",
        "-",
    ),  # 0xc073, RFC6367
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256": (
        0xC086,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CAMELLIA-128-GCM",
        "SHA256",
        "-",
    ),  # 0xc086, RFC6367
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384": (
        0xC087,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CAMELLIA-256-GCM",
        "SHA384",
        "-",
    ),  # 0xc087, RFC6367
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": (
        0xC0AC,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-128-CCM",
        "SHA256",
        "-",
    ),  # 0xc0ac, RFC7251
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": (
        0xC0AD,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-256-CCM",
        "SHA256",
        "-",
    ),  # 0xc0ad, RFC7251
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8": (
        0xC0AE,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-128-CCM-8",
        "SHA256",
        "-",
    ),  # 0xc0ae, RFC7251
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8": (
        0xC0AF,
        "1.2",
        "ECDHE",
        "ECDSA",
        "AES-256-CCM-8",
        "SHA256",
        "-",
    ),  # 0xc0af, RFC7251
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": (
        0xCC19,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CHACHA20-POLY1305",
        "SHA256",
        "-",
    ),  # 0xcc19, RFC7905
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_DRAFT": (
        0xCC19,
        "1.2",
        "ECDHE",
        "ECDSA",
        "CHACHA20-POLY1305-OLD",
        "SHA256",
        "-",
    ),
    # ---- Original FakeTLS ----
    "FAKETLS_XOR_AND": (
        0xFF00,
        "-",
        "-",
        "-",
        "XOR/AND",
        "-",
        "-",
    ),  # BADCALL
    "FAKETLS_RC4": (
        0xFF01,
        "-",
        "-",
        "-",
        "RC4-128",
        "-",
        "-",
    ),  # PEBBLEDASH
    "FAKETLS_XOR": (
        0xFF02,
        "-",
        "-",
        "-",
        "XOR",
        "-",
        "-",
    ),
    "FAKETLS_AES256_CBC": (
        0xFF03,
        "-",
        "-",
        "-",
        "AES-256-CBC",
        "-",
        "-",
    ),
}

MAPPING = {
    "TLS1.3_TLS_CHACHA20_POLY1305_SHA256": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
    "TLS1.3_TLS_AES_256_GCM_SHA384": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_AES_256_GCM_SHA384",
    ),
    "TLS1.3_TLS_AES_128_GCM_SHA256": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_AES_128_GCM_SHA256",
    ),
    "TLS1.2_ECDHE-ECDSA-CHACHA20-POLY1305": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    "TLS1.2_ECDHE-ECDSA-AES256-GCM-SHA384": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ),
    "TLS1.2_ECDHE-ECDSA-AES128-GCM-SHA256": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ),
    "TLS1.2_ECDHE-ECDSA-AES256-SHA384": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    ),
    "TLS1.2_ECDHE-ECDSA-AES128-SHA256": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    ),
    "TLS1.2_ECDHE-ECDSA-AES256-SHA": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    ),
    "TLS1.2_ECDHE-ECDSA-AES128-SHA": (
        "OpenSSL",
        OPENSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    ),
    "TLS1-3-CHACHA20-POLY1305-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
    "TLS1-3-AES-256-GCM-SHA384": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_AES_256_GCM_SHA384",
    ),
    "TLS1-3-AES-128-GCM-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_AES_128_GCM_SHA256",
    ),
    "TLS1-3-AES-128-CCM-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_AES_128_CCM_SHA256",
    ),
    "TLS1-3-AES-128-CCM-8-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_AES_128_CCM_8_SHA256",
    ),
    "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-256-CCM": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-128-CCM": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    ),
    "TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    ),
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    ),
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    ),
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    ),
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256": (
        "Mbed TLS",
        MBEDTLS_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    ),
    "TLS13-CHACHA20-POLY1305-SHA256": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
    "TLS13-AES256-GCM-SHA384": ("wolfSSL", WOLFSSL_VERSION, "TLS_AES_256_GCM_SHA384"),
    "TLS13-AES128-GCM-SHA256": ("wolfSSL", WOLFSSL_VERSION, "TLS_AES_128_GCM_SHA256"),
    "TLS13-AES128-CCM-SHA256": ("wolfSSL", WOLFSSL_VERSION, "TLS_AES_128_CCM_SHA256"),
    "TLS13-AES128-CCM-8-SHA256": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_AES_128_CCM_8_SHA256",
    ),
    "TLS13-AES128-CCM8-SHA256": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_AES_128_CCM_8_SHA256",
    ),
    "TLS13-SHA256-SHA256": ("wolfSSL", WOLFSSL_VERSION, "TLS_SHA256_SHA256"),
    "TLS13-SHA384-SHA384": ("wolfSSL", WOLFSSL_VERSION, "TLS_SHA384_SHA384"),
    "ECDHE-ECDSA-CHACHA20-POLY1305": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    "ECDHE-ECDSA-CHACHA20-POLY1305-OLD": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_DRAFT",
    ),
    "ECDHE-ECDSA-AES256-GCM-SHA384": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ),
    "ECDHE-ECDSA-AES128-GCM-SHA256": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ),
    "ECDHE-ECDSA-AES256-SHA384": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    ),
    "ECDHE-ECDSA-AES128-SHA256": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    ),
    "ECDHE-ECDSA-AES256-SHA": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    ),
    "ECDHE-ECDSA-AES128-SHA": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    ),
    "ECDHE-ECDSA-AES128-CCM": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    ),
    "ECDHE-ECDSA-AES256-CCM-8": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    ),
    "ECDHE-ECDSA-AES256-CCM8": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    ),
    "ECDHE-ECDSA-AES128-CCM-8": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    ),
    "ECDHE-ECDSA-AES128-CCM8": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    ),
    "ECDHE-ECDSA-RC4-SHA": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    ),
    "ECDHE-ECDSA-DES-CBC3-SHA": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    ),
    "ECDHE-ECDSA-NULL-SHA": (
        "wolfSSL",
        WOLFSSL_VERSION,
        "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    ),
    "FAKETLS-XOR-AND": (
        "FakeTLS",
        FAKETLS_VERSION,
        "FAKETLS_XOR_AND",
    ),
    "FAKETLS-RC4": (
        "FakeTLS",
        FAKETLS_VERSION,
        "FAKETLS_RC4",
    ),
    "FAKETLS-XOR": (
        "FakeTLS",
        FAKETLS_VERSION,
        "FAKETLS_XOR",
    ),
    "FAKETLS-AES256-CBC": (
        "FakeTLS",
        FAKETLS_VERSION,
        "FAKETLS_AES256_CBC",
    ),
}

FEATURES = [
    "entropy",  # Shannon entropy (of byte stream)
    "monobit_s_n",  # NIST SP800-22 Monobit test S_n value
    "monobit_s_obs",  # NIST SP800-22 Monobit test S_obs value
    "monobit_p",  # NIST SP800-22 Monobit test p value
    "runs_v_n_obs",  # NIST SP800-22 Runs test V_n(obs) value
    "runs_p",  # NIST SP800-22 Runs test p value
    "cumsum_mode0_z",  # NIST SP800-22 Cumsum test (mode 0) z value
    "cumsum_mode0_p",  # NIST SP800-22 Cumsum test (mode 0) p value
    "cumsum_mode1_z",  # NIST SP800-22 Cumsum test (mode 1) z value
    "cumsum_mode1_p",  # NIST SP800-22 Cumsum test (mode 1) p value
]

HEADER_CORE = [
    "src_file",  # Source file (*_hex.txt)
    "bytes",  # Data size [byte]
    "bytes_per_packet",  # Data size per packet("|" separated) [byte]
    "tls_library",  # TLS library
    "tls_library_version",  # TLS library version
    "tls_cipher_suites",  # TLS Cipher suites (IANA Description format)
    "tls_cipher_suites_id",  # TLS Cipher suites Value (0-65535)
    "tls_version",  # TLS version
    "tls12_key_exchange",  # TLS Key-exchange algorithm
    "tls12_authentication",  # TLS Authentication algorithm
    "tls_encryption",  # TLS Encryption algorithm
    "tls_hmac",  # TLS HMAC algorithm
    "tls13_hash",  # TLS Hash algorithm used with HKDF(TLS1.3 only)
    "exfiltrated_comand",  # Simulated exfiltrated command
]

def calc_entropy(input: bytes):
    total = len(input)
    counter = Counter(input)

    p = np.array([float(c) / total for c in counter.values()])
    entropy = np.sum(-p * np.log2(p))

    return entropy


def calc_monobit(input: bytes):
    input_bin = "".join([format(b, "08b") for b in input])
    n = len(input_bin)
    counter = Counter(input_bin)

    S_n = counter["1"] - counter["0"]
    S_obs = abs(S_n) / np.sqrt(n)
    P_val = math.erfc(S_obs / np.sqrt(2))

    return S_n, S_obs, P_val


def calc_runs(input: bytes):
    input_bin = "".join([format(b, "08b") for b in input])
    n = len(input_bin)
    counter = Counter(input_bin)

    pie = float(counter["1"]) / n
    tau = float(2) / np.sqrt(n)

    r = lambda k: int(input_bin[k] != input_bin[k + 1])
    V_n_obs = sum([r(k) for k in range(n - 1)]) + 1

    numerator = abs(V_n_obs - 2 * n * pie * (1 - pie))
    denominator = 2 * np.sqrt(2 * n) * pie * (1 - pie)
    P_val = math.erfc(float(numerator) / denominator)

    return V_n_obs, P_val


def calc_cumsum(input: bytes, mode=0):
    input_bin = "".join([format(b, "08b") for b in input])

    X = [2 * int(x) - 1 for x in input_bin]
    modeX = list(reversed(X)) if mode == 1 else X

    S_i = np.cumsum(modeX)
    z = max(max(S_i), abs(min(S_i)))

    n = len(modeX)

    k_start = int((-n / z + 1) / 4)
    k_stop = int((n / z - 1) / 4)
    term2 = sum(
        [
            norm.cdf((4 * k + 1) * z / np.sqrt(n))
            - norm.cdf((4 * k - 1) * z / np.sqrt(n))
            for k in range(k_start, k_stop + 1)
        ]
    )

    k_start = int((-n / z - 3) / 4)
    k_stop = int((n / z - 1) / 4)
    term3 = sum(
        [
            norm.cdf((4 * k + 3) * z / np.sqrt(n))
            - norm.cdf((4 * k + 1) * z / np.sqrt(n))
            for k in range(k_start, k_stop + 1)
        ]
    )

    P_val = 1 - term2 + term3

    return z, P_val


def calc_features(input: bytes):
    result = {"entropy": calc_entropy(input)}

    S_n, S_obs, P_val = calc_monobit(input)
    result["monobit_s_n"] = S_n
    result["monobit_s_obs"] = S_obs
    result["monobit_p"] = P_val

    V_obs, P_val = calc_runs(input)
    result["runs_v_n_obs"] = V_obs
    result["runs_p"] = P_val

    z, P_val = calc_cumsum(input)
    result["cumsum_mode0_z"] = z
    result["cumsum_mode0_p"] = P_val

    z, P_val = calc_cumsum(input, 1)
    result["cumsum_mode1_z"] = z
    result["cumsum_mode1_p"] = P_val

    return result


def parse_path(path: pathlib.Path):
    tls, command, hex = path.stem.rsplit("_", maxsplit=2)
    tls_info = MAPPING[tls]
    tls_params = CIPHER_SUITES[tls_info[2]]

    return {
        "tls_library": tls_info[0],
        "tls_library_version": tls_info[1],
        "tls_cipher_suites": tls_info[2],
        "tls_cipher_suites_id": tls_params[0],
        "tls_version": tls_params[1],
        "tls12_key_exchange": tls_params[2],
        "tls12_authentication": tls_params[3],
        "tls_encryption": tls_params[4],
        "tls_hmac": tls_params[5],
        "tls13_hash": tls_params[6],
        "exfiltrated_comand": command,
    }


def main():
    output_dir = pathlib.Path(OUTPUT_FILE).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w") as csvfile:
        header = HEADER_CORE + FEATURES
        for feature, suffix in itertools.product(
            FEATURES, list(range(10, 210, 10)) + ["per_packet"]
        ):
            header.append(f"{feature}_{suffix}")

        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()

        for path in pathlib.Path(HEXTEXT_DIR).glob("**/*_hex.txt"):
            print(path)
            result = {"src_file": str(path)}
            result |= parse_path(path)

            with open(path, "r") as hexfile:
                contents = hexfile.readlines()
            try:
                full_content_bytes = bytes.fromhex("".join(contents))
            except:
                print(("".join(contents))[26895:268100])
            result["bytes"] = len(full_content_bytes)
            result["bytes_per_packet"] = "|".join(
                [str(len(bytes.fromhex(line))) for line in contents]
            )

            result |= calc_features(full_content_bytes)

            features_per_packet = [
                calc_features(bytes.fromhex(line)) for line in contents
            ]

            for name in FEATURES:
                result[f"{name}_per_packet"] = "|".join(
                    [str(f[name]) for f in features_per_packet]
                )

            for size in range(10, 210, 10):
                features = calc_features(
                    full_content_bytes[: min(len(full_content_bytes), size)]
                )

                for name in FEATURES:
                    result[f"{name}_{size}"] = features[name]

            writer.writerow(result)

            if not result.get("tls_encryption"):
                print(result)

            # print(result)


if __name__ == "__main__":
    main()
