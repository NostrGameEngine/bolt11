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

import java.util.ArrayList;
import java.util.List;

public final class Bolt11TagsObject {

    private String paymentHash;
    private String paymentSecret;
    private String description;
    private String payeePubkey;
    private String descriptionHash;
    private String paymentMetadata;
    private Long expiry;
    private Long minFinalCltvExpiry;
    private Bolt11FallbackAddress fallback;
    private List<Bolt11RoutingInfoRoute> routeHints;
    private Bolt11FeatureBits features;
    private final List<Bolt11UnknownTagData> unknownTags = new ArrayList<>();

    public static Bolt11TagsObject fromTags(List<Bolt11Tag> tags) {
        Bolt11TagsObject out = new Bolt11TagsObject();
        for (Bolt11Tag tag : tags) {
            Bolt11TagName name = tag.tagName();
            Object data = tag.data();
            switch (name) {
                case PAYMENT_HASH:
                    out.paymentHash = data == null ? null : String.valueOf(data);
                    break;
                case PAYMENT_SECRET:
                    out.paymentSecret = data == null ? null : String.valueOf(data);
                    break;
                case DESCRIPTION:
                    out.description = data == null ? null : String.valueOf(data);
                    break;
                case PAYEE_PUBKEY:
                    out.payeePubkey = data == null ? null : String.valueOf(data);
                    break;
                case DESCRIPTION_HASH:
                    out.descriptionHash = data == null ? null : String.valueOf(data);
                    break;
                case PAYMENT_METADATA:
                    out.paymentMetadata = data == null ? null : String.valueOf(data);
                    break;
                case EXPIRY:
                    out.expiry = data instanceof Number ? ((Number) data).longValue() : null;
                    break;
                case MIN_FINAL_CLTV_EXPIRY:
                    out.minFinalCltvExpiry = data instanceof Number ? ((Number) data).longValue() : null;
                    break;
                case FALLBACK:
                    out.fallback = data instanceof Bolt11FallbackAddress ? ((Bolt11FallbackAddress) data) : null;
                    break;
                case ROUTE_HINTS:
                    out.routeHints = new ArrayList<>();
                    if (data instanceof List) {
                        for (Object item : (List<?>) data) {
                            if (item instanceof Bolt11RoutingInfoRoute) {
                                out.routeHints.add((Bolt11RoutingInfoRoute) item);
                            }
                        }
                    }
                    break;
                case FEATURES:
                    out.features = data instanceof Bolt11FeatureBits ? (Bolt11FeatureBits) data : null;
                    break;
                case UNKNOWN:
                    if (data instanceof Bolt11UnknownTagData) {
                        out.unknownTags.add((Bolt11UnknownTagData) data);
                    }
                    break;
                default:
                    break;
            }
        }
        return out;
    }

    public Bolt11TagsObject copy() {
        Bolt11TagsObject out = new Bolt11TagsObject();
        out.paymentHash = paymentHash;
        out.paymentSecret = paymentSecret;
        out.description = description;
        out.payeePubkey = payeePubkey;
        out.descriptionHash = descriptionHash;
        out.paymentMetadata = paymentMetadata;
        out.expiry = expiry;
        out.minFinalCltvExpiry = minFinalCltvExpiry;
        out.fallback = fallback == null ? null : fallback.copy();
        if (routeHints != null) {
            out.routeHints = new ArrayList<>(routeHints.size());
            for (Bolt11RoutingInfoRoute r : routeHints) {
                out.routeHints.add(r.copy());
            }
        }
        out.features = features == null ? null : features.copy();
        for (Bolt11UnknownTagData t : unknownTags) {
            out.unknownTags.add(t.copy());
        }
        return out;
    }
}
