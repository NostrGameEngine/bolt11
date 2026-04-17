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

public final class Bolt11RoutingInfoRoute {

    private String pubkey;
    private String shortChannelId;
    private BigInteger feeBaseMsat;
    private BigInteger feeProportionalMillionths;
    private Long cltvExpiryDelta;

    public String getPubkey() {
        return pubkey;
    }

    public void setPubkey(String pubkey) {
        this.pubkey = pubkey;
    }

    public String getShortChannelId() {
        return shortChannelId;
    }

    public void setShortChannelId(String shortChannelId) {
        this.shortChannelId = shortChannelId;
    }

    public BigInteger getFeeBaseMsat() {
        return feeBaseMsat;
    }

    public void setFeeBaseMsat(BigInteger feeBaseMsat) {
        this.feeBaseMsat = feeBaseMsat;
    }

    public BigInteger getFeeProportionalMillionths() {
        return feeProportionalMillionths;
    }

    public void setFeeProportionalMillionths(BigInteger feeProportionalMillionths) {
        this.feeProportionalMillionths = feeProportionalMillionths;
    }

    public Long getCltvExpiryDelta() {
        return cltvExpiryDelta;
    }

    public void setCltvExpiryDelta(Long cltvExpiryDelta) {
        this.cltvExpiryDelta = cltvExpiryDelta;
    }

    public Bolt11RoutingInfoRoute copy() {
        Bolt11RoutingInfoRoute out = new Bolt11RoutingInfoRoute();
        out.pubkey = pubkey;
        out.shortChannelId = shortChannelId;
        out.feeBaseMsat = feeBaseMsat;
        out.feeProportionalMillionths = feeProportionalMillionths;
        out.cltvExpiryDelta = cltvExpiryDelta;
        return out;
    }
}
