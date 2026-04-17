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

import java.util.HashMap;
import java.util.Map;

public enum Bolt11TagName {
    PAYMENT_HASH("payment_hash", 1),
    PAYMENT_SECRET("payment_secret", 16),
    DESCRIPTION("description", 13),
    PAYEE_PUBKEY("payee_pubkey", 19),
    DESCRIPTION_HASH("description_hash", 23),
    EXPIRY("expiry", 6),
    MIN_FINAL_CLTV_EXPIRY("min_final_cltv_expiry", 24),
    PAYMENT_METADATA("payment_metadata", 27),
    FALLBACK("fallback", 9),
    ROUTE_HINTS("route_hints", 3),
    FEATURES("features", 5),
    UNKNOWN("unknownTag", -1);

    private static final Map<String, Bolt11TagName> BY_WIRE_NAME = new HashMap<>();
    private static final Map<Integer, Bolt11TagName> BY_CODE = new HashMap<>();

    static {
        for (Bolt11TagName value : values()) {
            BY_WIRE_NAME.put(value.wireName, value);
            if (value.code >= 0) {
                BY_CODE.put(value.code, value);
            }
        }
    }

    private final String wireName;
    private final int code;

    Bolt11TagName(String wireName, int code) {
        this.wireName = wireName;
        this.code = code;
    }

    public String wireName() {
        return wireName;
    }

    public int code() {
        return code;
    }

    public static Bolt11TagName fromWireName(String wireName) {
        Bolt11TagName value = BY_WIRE_NAME.get(wireName);
        return value == null ? UNKNOWN : value;
    }

    public static Bolt11TagName fromCode(int code) {
        Bolt11TagName value = BY_CODE.get(code);
        return value == null ? UNKNOWN : value;
    }
}
