/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2026, Riccardo Balbo
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.ngengine.bolt11;

import java.math.BigInteger;
import java.util.Arrays;
import org.ngengine.platform.NGEPlatform;

final class Base58Check {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);
    private static final int MAX_BASE58_ADDRESS_LENGTH = 256;

    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            INDEXES[ALPHABET.charAt(i)] = i;
        }
    }

    private Base58Check() {}

    static String toBase58Check(byte[] hash, int version) {
        byte[] payload = new byte[1 + hash.length];
        payload[0] = (byte) (version & 0xff);
        System.arraycopy(hash, 0, payload, 1, hash.length);
        byte[] checksum = Arrays.copyOf(doubleSha256(payload), 4);
        return encodeBase58(concat(payload, checksum));
    }

    static Decoded fromBase58Check(String address) {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Invalid base58 address");
        }
        if (address.length() > MAX_BASE58_ADDRESS_LENGTH) {
            throw new IllegalArgumentException("Base58 address is too long");
        }
        byte[] raw = decodeBase58(address);
        if (raw.length < 5) {
            throw new IllegalArgumentException("Invalid base58 address");
        }
        byte[] payload = Arrays.copyOf(raw, raw.length - 4);
        byte[] checksum = Arrays.copyOfRange(raw, raw.length - 4, raw.length);
        byte[] expected = Arrays.copyOf(doubleSha256(payload), 4);
        if (!Arrays.equals(checksum, expected)) {
            throw new IllegalArgumentException("Invalid base58 checksum");
        }
        int version = payload[0] & 0xff;
        byte[] hash = Arrays.copyOfRange(payload, 1, payload.length);
        return new Decoded(version, hash);
    }

    private static byte[] doubleSha256(byte[] in) {
        return NGEPlatform.get().sha256(NGEPlatform.get().sha256(in));
    }

    private static String encodeBase58(byte[] input) {
        BigInteger n = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (n.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divRem = n.divideAndRemainder(FIFTY_EIGHT);
            n = divRem[0];
            sb.append(ALPHABET.charAt(divRem[1].intValue()));
        }
        for (byte b : input) {
            if (b == 0) {
                sb.append('1');
            } else {
                break;
            }
        }
        return sb.reverse().toString();
    }

    private static byte[] decodeBase58(String input) {
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 128 || INDEXES[c] < 0) {
                throw new IllegalArgumentException("Invalid base58 character");
            }
            n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(INDEXES[c]));
        }

        byte[] raw = n.toByteArray();
        if (raw.length > 0 && raw[0] == 0) {
            raw = Arrays.copyOfRange(raw, 1, raw.length);
        }

        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == '1') {
            zeros++;
        }

        byte[] out = new byte[zeros + raw.length];
        System.arraycopy(raw, 0, out, zeros, raw.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static final class Decoded {

        private final int version;
        private final byte[] hash;

        private Decoded(int version, byte[] hash) {
            this.version = version;
            this.hash = Arrays.copyOf(hash, hash.length);
        }

        int version() {
            return version;
        }

        byte[] hash() {
            return Arrays.copyOf(hash, hash.length);
        }
    }
}
