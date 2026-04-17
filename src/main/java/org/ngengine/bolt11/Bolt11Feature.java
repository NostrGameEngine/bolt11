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

public enum Bolt11Feature {
    OPTION_DATA_LOSS_PROTECT("option_data_loss_protect", 0),
    INITIAL_ROUTING_SYNC("initial_routing_sync", 2),
    OPTION_UPFRONT_SHUTDOWN_SCRIPT("option_upfront_shutdown_script", 4),
    GOSSIP_QUERIES("gossip_queries", 6),
    VAR_ONION_OPTIN("var_onion_optin", 8),
    GOSSIP_QUERIES_EX("gossip_queries_ex", 10),
    OPTION_STATIC_REMOTEKEY("option_static_remotekey", 12),
    PAYMENT_SECRET("payment_secret", 14),
    BASIC_MPP("basic_mpp", 16),
    OPTION_SUPPORT_LARGE_CHANNEL("option_support_large_channel", 18);

    private static final Map<String, Bolt11Feature> BY_WIRE_NAME = new HashMap<>();
    private static final Map<Integer, Bolt11Feature> BY_REQUIRED_BIT = new HashMap<>();
    private static final Map<Integer, Bolt11Feature> BY_SUPPORTED_BIT = new HashMap<>();

    static {
        for (Bolt11Feature value : values()) {
            BY_WIRE_NAME.put(value.wireName, value);
            BY_REQUIRED_BIT.put(value.requiredBitIndex(), value);
            BY_SUPPORTED_BIT.put(value.supportedBitIndex(), value);
        }
    }

    private final String wireName;
    private final int requiredBitIndex;

    Bolt11Feature(String wireName, int requiredBitIndex) {
        this.wireName = wireName;
        this.requiredBitIndex = requiredBitIndex;
    }

    public String wireName() {
        return wireName;
    }

    public int requiredBitIndex() {
        return requiredBitIndex;
    }

    public int supportedBitIndex() {
        return requiredBitIndex + 1;
    }

    public static Bolt11Feature fromWireName(String wireName) {
        return BY_WIRE_NAME.get(wireName);
    }

    public static Bolt11Feature fromRequiredBitIndex(int bitIndex) {
        return BY_REQUIRED_BIT.get(bitIndex);
    }

    public static Bolt11Feature fromSupportedBitIndex(int bitIndex) {
        return BY_SUPPORTED_BIT.get(bitIndex);
    }
}
