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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public enum Bolt11NetworkType {
    MAINNET("bc", 0x00, 0x05, Arrays.asList(0, 1)),
    TESTNET("tb", 0x6f, 0xc4, Arrays.asList(0, 1)),
    SIGNET("tbs", 0x6f, 0xc4, Arrays.asList(0, 1)),
    REGTEST("bcrt", 0x6f, 0xc4, Arrays.asList(0, 1)),
    SIMNET("sb", 0x3f, 0x7b, Arrays.asList(0, 1));

    private static final Map<String, Bolt11NetworkType> BY_BECH32 = new HashMap<>();

    static {
        for (Bolt11NetworkType value : values()) {
            BY_BECH32.put(value.bech32, value);
        }
    }

    private final String bech32;
    private final int pubKeyHash;
    private final int scriptHash;
    private final List<Integer> validWitnessVersions;

    Bolt11NetworkType(String bech32, int pubKeyHash, int scriptHash, List<Integer> validWitnessVersions) {
        this.bech32 = bech32;
        this.pubKeyHash = pubKeyHash;
        this.scriptHash = scriptHash;
        this.validWitnessVersions = List.copyOf(validWitnessVersions);
    }

    public String bech32() {
        return bech32;
    }

    public int pubKeyHash() {
        return pubKeyHash;
    }

    public int scriptHash() {
        return scriptHash;
    }

    public List<Integer> validWitnessVersions() {
        return validWitnessVersions;
    }

    public static Bolt11NetworkType fromBech32(String bech32) {
        return BY_BECH32.get(bech32);
    }
}
