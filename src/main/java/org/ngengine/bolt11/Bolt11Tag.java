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
import org.ngengine.platform.NGEUtils;

public final class Bolt11Tag {

    private final Bolt11TagName tagName;
    private final Object value;

    private Bolt11Tag(Bolt11TagName tagName, Object value) {
        this.tagName = tagName;
        this.value = validateValue(tagName, value);
    }

    public static Bolt11Tag of(Bolt11TagName tagName, Object value) {
        return new Bolt11Tag(tagName, value);
    }

    public static Bolt11Tag of(String tagName, Object value) {
        return new Bolt11Tag(Bolt11TagName.fromWireName(tagName), value);
    }

    public Bolt11TagName tagName() {
        return tagName;
    }

    public String tagNameWire() {
        return tagName.wireName();
    }

    public Object data() {
        return value;
    }

    public Object getValue() {
        return value;
    }

    public String getValueAsString() {
        return String.valueOf(value);
    }

    public Long getValueAsLong() {
        if (value instanceof Number) {
            return NGEUtils.safeLong(value);
        }
        throw new IllegalArgumentException("Tag value is not a numeric type");
    }

    public byte[] getValueAsBytes() {
        if (value instanceof String) {
            byte[] result = NGEUtils.hexToByteArray(getValueAsString());
            if (result == null) {
                throw new IllegalArgumentException("Tag value is not a valid hex string");
            }
            return result;
        }
        throw new IllegalArgumentException("Tag value is not a hex string");
    }

    public Bolt11FallbackAddress getValueAsFallbackAddress() {
        if (value instanceof Bolt11FallbackAddress) {
            return (Bolt11FallbackAddress) value;
        }
        throw new IllegalArgumentException("Tag value is not a fallback address");
    }

    @SuppressWarnings("unchecked")
    public List<Bolt11RoutingInfoRoute> getValueAsRoutingInfo() {
        if (value instanceof List) {
            return (List<Bolt11RoutingInfoRoute>) value;
        }
        throw new IllegalArgumentException("Tag value is not routing info");
    }

    public Bolt11FeatureBits getValueAsFeatureBits() {
        if (value instanceof Bolt11FeatureBits) {
            return (Bolt11FeatureBits) value;
        }
        throw new IllegalArgumentException("Tag value is not feature bits");
    }

    public Bolt11UnknownTagData getValueAsUnknownTagData() {
        if (value instanceof Bolt11UnknownTagData) {
            return (Bolt11UnknownTagData) value;
        }
        throw new IllegalArgumentException("Tag value is not unknown tag data");
    }

    public Bolt11Tag copy() {
        return new Bolt11Tag(tagName, copyValue(value));
    }

    private static Object copyValue(Object val) {
        if (val instanceof Bolt11FallbackAddress) {
            return ((Bolt11FallbackAddress) val).copy();
        }
        if (val instanceof Bolt11FeatureBits) {
            return ((Bolt11FeatureBits) val).copy();
        }
        if (val instanceof Bolt11UnknownTagData) {
            return ((Bolt11UnknownTagData) val).copy();
        }
        if (val instanceof Bolt11RoutingInfoRoute) {
            return ((Bolt11RoutingInfoRoute) val).copy();
        }
        if (val instanceof List) {
            List<?> src = (List<?>) val;
            List<Object> out = new ArrayList<>(src.size());
            for (Object item : src) {
                out.add(copyValue(item));
            }
            return out;
        }
        return val;
    }

    private static Object validateValue(Bolt11TagName tagName, Object val) {
        if (tagName == null) {
            throw new IllegalArgumentException("Unknown tag key: null");
        }
        switch (tagName) {
            case FALLBACK:
                if (!(val instanceof Bolt11FallbackAddress)) {
                    throw new IllegalArgumentException("fallback data is invalid");
                }
                return val;
            case ROUTE_HINTS:
                if (!(val instanceof List)) {
                    throw new IllegalArgumentException("route_hints data is invalid");
                }
                for (Object item : (List<?>) val) {
                    if (!(item instanceof Bolt11RoutingInfoRoute)) {
                        throw new IllegalArgumentException("route_hints data is invalid");
                    }
                }
                return val;
            case FEATURES:
                if (!(val instanceof Bolt11FeatureBits)) {
                    throw new IllegalArgumentException("features data is invalid");
                }
                return val;
            case UNKNOWN:
                if (!(val instanceof Bolt11UnknownTagData)) {
                    throw new IllegalArgumentException("Unknown tag data is invalid");
                }
                return val;
            default:
                return val;
        }
    }
}
