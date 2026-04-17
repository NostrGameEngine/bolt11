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
import java.util.ArrayList;
import java.util.List;

final class Bolt11WireUtils {

    private Bolt11WireUtils() {}

    static List<Integer> convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        List<Integer> ret = new ArrayList<>();
        for (byte value : data) {
            int b = value & 0xff;
            if ((b >> fromBits) != 0) {
                throw new IllegalArgumentException("Invalid data range for convertBits");
            }
            acc = (acc << fromBits) | b;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.add((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                ret.add((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new IllegalArgumentException("Invalid padding in convertBits");
        }
        return ret;
    }

    static byte[] convertBitsToBytes(List<Integer> data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        List<Integer> ret = new ArrayList<>();
        for (int value : data) {
            if ((value >> fromBits) != 0) {
                throw new IllegalArgumentException("Invalid data range for convertBits");
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.add((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                ret.add((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new IllegalArgumentException("Invalid padding in convertBits");
        }
        byte[] out = new byte[ret.size()];
        for (int i = 0; i < ret.size(); i++) {
            out[i] = (byte) (ret.get(i) & 0xff);
        }
        return out;
    }

    static List<Integer> unsignedByteBufferToList(ByteBuffer in) {
        ByteBuffer src = in.slice();
        List<Integer> out = new ArrayList<>(src.remaining());
        while (src.hasRemaining()) {
            out.add(src.get() & 0xff);
        }
        return out;
    }

    static byte[] listToUnsignedByteArray(List<Integer> data, int maxValue, String errorMessage) {
        byte[] out = new byte[data.size()];
        for (int i = 0; i < data.size(); i++) {
            int value = data.get(i);
            if (value < 0 || value > maxValue) {
                throw new IllegalArgumentException(errorMessage);
            }
            out[i] = (byte) value;
        }
        return out;
    }

    static byte[] padLeftUnsignedBytes(List<Integer> words, int size) {
        List<Integer> padded = new ArrayList<>();
        for (int i = 0; i < size - 1; i++) {
            padded.add(0);
        }
        padded.addAll(words);
        if (padded.size() > size) {
            padded = padded.subList(padded.size() - size, padded.size());
        }
        byte[] out = new byte[padded.size()];
        for (int i = 0; i < padded.size(); i++) {
            out[i] = (byte) (padded.get(i) & 0xff);
        }
        return out;
    }
}
