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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class Bolt11Invoice {

    private Bolt11NetworkType network;
    private List<Bolt11Tag> tags = new ArrayList<>();
    private Instant timestamp;
    private BigInteger satoshis;
    private BigInteger millisatoshis;
    private Instant timeExpireDate;
    private Boolean complete;
    private String paymentRequest;
    private String payeeNodeKey;
    private String signature;
    private Integer recoveryFlag;

    public Bolt11Invoice copy() {
        Bolt11Invoice out = new Bolt11Invoice();
        out.network = network;
        if (tags == null) {
            out.tags = null;
        } else {
            out.tags = new ArrayList<>(tags.size());
            for (Bolt11Tag t : tags) {
                out.tags.add(t.copy());
            }
        }
        out.timestamp = timestamp;
        out.satoshis = satoshis;
        out.millisatoshis = millisatoshis;
        out.timeExpireDate = timeExpireDate;
        out.complete = complete;
        out.paymentRequest = paymentRequest;
        out.payeeNodeKey = payeeNodeKey;
        out.signature = signature;
        out.recoveryFlag = recoveryFlag;
        return out;
    }

    public Bolt11NetworkType getNetwork() {
        return network;
    }

    public void setNetwork(Bolt11NetworkType network) {
        this.network = network;
    }

    public List<Bolt11Tag> getTags() {
        return tags;
    }

    public void setTags(List<Bolt11Tag> tags) {
        this.tags = tags;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public void setTimestamp(long epochSeconds) {
        this.timestamp = Instant.ofEpochSecond(epochSeconds);
    }

    public BigInteger getSatoshis() {
        return satoshis;
    }

    public void setSatoshis(BigInteger satoshis) {
        this.satoshis = satoshis;
    }

    public BigInteger getMillisatoshis() {
        return millisatoshis;
    }

    public void setMillisatoshis(BigInteger millisatoshis) {
        this.millisatoshis = millisatoshis;
    }

    public Instant getTimeExpireDate() {
        return timeExpireDate;
    }

    public void setTimeExpireDate(Instant timeExpireDate) {
        this.timeExpireDate = timeExpireDate;
    }

    public void setTimeExpireDate(long epochSeconds) {
        this.timeExpireDate = Instant.ofEpochSecond(epochSeconds);
    }

    public Boolean getComplete() {
        return complete;
    }

    public void setComplete(Boolean complete) {
        this.complete = complete;
    }

    public String getPaymentRequest() {
        return paymentRequest;
    }

    public void setPaymentRequest(String paymentRequest) {
        this.paymentRequest = paymentRequest;
    }

    public String getPayeeNodeKey() {
        return payeeNodeKey;
    }

    public void setPayeeNodeKey(String payeeNodeKey) {
        this.payeeNodeKey = payeeNodeKey;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public Integer getRecoveryFlag() {
        return recoveryFlag;
    }

    public void setRecoveryFlag(Integer recoveryFlag) {
        this.recoveryFlag = recoveryFlag;
    }

    public Bolt11Tag getTag(Bolt11TagName name) {
        if (tags == null) return null;
        for (Bolt11Tag tag : tags) {
            if (tag.tagName() == name) return tag;
        }
        return null;
    }
}
