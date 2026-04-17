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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.ngengine.bech32.Bech32;
import org.ngengine.bech32.Bech32ChecksumVariant;
import org.ngengine.bech32.Bech32EncodingException;
import org.ngengine.bech32.Bech32Exception;
import org.ngengine.bech32.Bech32m;

final class SegwitAddress {

    private static final int MAX_BECH32_ADDRESS_LENGTH = 512;
    private static final int SEGWIT_PROGRAM_MIN_LENGTH = 2;
    private static final int SEGWIT_PROGRAM_MAX_LENGTH = 40;

    private final String prefix;
    private final int version;
    private final byte[] data;

    private SegwitAddress(String prefix, int version, byte[] data) {
        this.prefix = prefix;
        this.version = version;
        this.data = data == null ? null : data.clone();
    }

    String prefix() {
        return prefix;
    }

    int version() {
        return version;
    }

    byte[] data() {
        return data == null ? null : data.clone();
    }

    static String toBech32(byte[] addressHash, int version, String hrp) throws Bech32EncodingException {
        List<Integer> words = new ArrayList<>();
        words.add(version);
        words.addAll(Bolt11WireUtils.convertBits(addressHash, 8, 5, true));
        byte[] wordBytes = Bolt11WireUtils.listToUnsignedByteArray(words, 31, "Invalid bech32 data range");
        if (version == 0) {
            return Bech32.bech32Encode(
                hrp.getBytes(StandardCharsets.UTF_8),
                ByteBuffer.wrap(wordBytes),
                Bech32.DataFormat.BITS_5
            );
        }
        return Bech32m.bech32mEncode(
            hrp.getBytes(StandardCharsets.UTF_8),
            ByteBuffer.wrap(wordBytes),
            Bech32.DataFormat.BITS_5
        );
    }

    static SegwitAddress fromBech32(String address) throws Bech32Exception {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Invalid bech32 address");
        }
        if (address.length() > MAX_BECH32_ADDRESS_LENGTH) {
            throw new IllegalArgumentException("Bech32 address is too long");
        }
        Bech32ChecksumVariant variant = new Bech32ChecksumVariant();
        ByteBuffer decodedData = Bech32.bech32Decode(address, -1, variant, Bech32.DataFormat.BITS_5);
        List<Integer> decodedWords = Bolt11WireUtils.unsignedByteBufferToList(decodedData);
        if (decodedWords.isEmpty()) {
            throw new IllegalArgumentException("Invalid bech32 address");
        }
        int version = decodedWords.get(0);
        if (version < 0 || version > 16) {
            throw new IllegalArgumentException("Invalid witness version");
        }

        List<Integer> dataWords = decodedWords.subList(1, decodedWords.size());
        byte[] data = Bolt11WireUtils.convertBitsToBytes(dataWords, 5, 8, false);
        if (data.length < SEGWIT_PROGRAM_MIN_LENGTH || data.length > SEGWIT_PROGRAM_MAX_LENGTH) {
            throw new IllegalArgumentException("Invalid witness program length");
        }

        boolean isBech32m = variant.getVariant() == Bech32ChecksumVariant.BECH32M_CONST;
        if (version == 0 && isBech32m) {
            throw new IllegalArgumentException("Invalid segwit v0 encoding");
        }
        if (version > 0 && !isBech32m) {
            throw new IllegalArgumentException("Invalid segwit v1+ encoding");
        }
        if (version == 0 && data.length != 20 && data.length != 32) {
            throw new IllegalArgumentException("Invalid segwit v0 program length");
        }

        return new SegwitAddress(new String(Bech32.hrp(address), StandardCharsets.UTF_8), version, data);
    }
}
