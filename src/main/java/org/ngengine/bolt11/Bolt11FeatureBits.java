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
import java.util.EnumMap;
import java.util.List;

public final class Bolt11FeatureBits {

    public static final class FeatureFlag {

        public enum FlagState {
            NONE(false, false),
            REQUIRED_ONLY(true, false),
            SUPPORTED_ONLY(false, true),
            REQUIRED_AND_SUPPORTED(true, true);

            private final boolean required;
            private final boolean supported;

            FlagState(boolean required, boolean supported) {
                this.required = required;
                this.supported = supported;
            }

            public boolean isRequired() {
                return required;
            }

            public boolean isSupported() {
                return supported;
            }

            public static FlagState fromBooleans(boolean required, boolean supported) {
                if (required && supported) {
                    return REQUIRED_AND_SUPPORTED;
                }
                if (required) {
                    return REQUIRED_ONLY;
                }
                if (supported) {
                    return SUPPORTED_ONLY;
                }
                return NONE;
            }
        }

        private FlagState state = FlagState.NONE;

        public static FeatureFlag of(boolean required, boolean supported) {
            FeatureFlag out = new FeatureFlag();
            out.state = FlagState.fromBooleans(required, supported);
            return out;
        }

        public static FeatureFlag of(FlagState state) {
            FeatureFlag out = new FeatureFlag();
            out.state = state == null ? FlagState.NONE : state;
            return out;
        }

        public boolean isRequired() {
            return state.isRequired();
        }

        public void setRequired(boolean required) {
            this.state = FlagState.fromBooleans(required, state.isSupported());
        }

        public boolean isSupported() {
            return state.isSupported();
        }

        public void setSupported(boolean supported) {
            this.state = FlagState.fromBooleans(state.isRequired(), supported);
        }

        public FlagState getState() {
            return state;
        }

        public void setState(FlagState state) {
            this.state = state == null ? FlagState.NONE : state;
        }

        public FeatureFlag copy() {
            return of(state);
        }
    }

    private final EnumMap<Bolt11Feature, FeatureFlag> features = new EnumMap<>(Bolt11Feature.class);
    private Integer wordLength;
    private int extraStartBit;
    private List<Boolean> extraBits = new ArrayList<>();
    private boolean extraHasRequired;

    public Bolt11FeatureBits() {
        for (Bolt11Feature feature : Bolt11Feature.values()) {
            features.put(feature, FeatureFlag.of(false, false));
        }
    }

    public static Bolt11FeatureBits defaults() {
        Bolt11FeatureBits out = new Bolt11FeatureBits();
        out.wordLength = 4;
        out.setFeature(Bolt11Feature.VAR_ONION_OPTIN, FeatureFlag.of(false, true));
        out.setFeature(Bolt11Feature.PAYMENT_SECRET, FeatureFlag.of(false, true));
        return out;
    }

    public FeatureFlag getFeature(Bolt11Feature feature) {
        return feature == null ? null : features.get(feature);
    }

    public FeatureFlag getFeatureOrDefault(Bolt11Feature feature) {
        FeatureFlag value = getFeature(feature);
        return value == null ? FeatureFlag.of(false, false) : value;
    }

    public void setFeature(Bolt11Feature feature, FeatureFlag value) {
        if (feature == null) {
            return;
        }
        features.put(feature, value == null ? FeatureFlag.of(false, false) : value);
    }

    public Integer getWordLength() {
        return wordLength;
    }

    public void setWordLength(Integer wordLength) {
        this.wordLength = wordLength;
    }

    public int getExtraStartBit() {
        return extraStartBit;
    }

    public void setExtraStartBit(int extraStartBit) {
        this.extraStartBit = extraStartBit;
    }

    public List<Boolean> getExtraBits() {
        return new ArrayList<>(extraBits);
    }

    public void setExtraBits(List<Boolean> extraBits) {
        this.extraBits = extraBits == null ? new ArrayList<>() : new ArrayList<>(extraBits);
    }

    public boolean isExtraHasRequired() {
        return extraHasRequired;
    }

    public void setExtraHasRequired(boolean extraHasRequired) {
        this.extraHasRequired = extraHasRequired;
    }

    public Bolt11FeatureBits copy() {
        Bolt11FeatureBits out = new Bolt11FeatureBits();
        out.wordLength = wordLength;
        out.features.clear();
        for (Bolt11Feature feature : Bolt11Feature.values()) {
            out.features.put(feature, getFeatureOrDefault(feature).copy());
        }
        out.extraStartBit = extraStartBit;
        out.extraBits = new ArrayList<>(extraBits);
        out.extraHasRequired = extraHasRequired;
        return out;
    }
}
