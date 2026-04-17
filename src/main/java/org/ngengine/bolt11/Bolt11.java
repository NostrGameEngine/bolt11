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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.ngengine.bech32.Bech32;
import org.ngengine.bech32.Bech32ChecksumVariant;
import org.ngengine.bech32.Bech32EncodingException;
import org.ngengine.bech32.Bech32Exception;
import org.ngengine.platform.NGEPlatform;
import org.ngengine.platform.NGEUtils;
import org.ngengine.platform.secp256k1.Secp256k1RecoverableSignature;

public final class Bolt11 {

    private Bolt11() {}

    private static final class UnsignedPayload {

        final String prefix;
        final List<Integer> dataWords;

        UnsignedPayload(String prefix, List<Integer> dataWords) {
            this.prefix = prefix;
            this.dataWords = dataWords;
        }
    }

    private static UnsignedPayload buildUnsignedPayload(Bolt11Invoice data) throws Bech32Exception {
        String prefix = "ln" + data.getNetwork().bech32();
        String hrpString;
        if (data.getMillisatoshis() != null && data.getSatoshis() != null) {
            hrpString = millisatToHrp(data.getMillisatoshis());
        } else if (data.getMillisatoshis() != null) {
            hrpString = millisatToHrp(data.getMillisatoshis());
        } else if (data.getSatoshis() != null) {
            hrpString = satToHrp(data.getSatoshis());
        } else {
            hrpString = "";
        }
        prefix += hrpString;

        long ts = data.getTimestamp().getEpochSecond();
        List<Integer> timestampWords = intBEToWords(ts, 5);
        while (timestampWords.size() < 7) {
            timestampWords.add(0, 0);
        }

        List<Integer> tagWords = new ArrayList<>();
        Bolt11NetworkType network = data.getNetwork();
        for (Bolt11Tag tag : data.getTags()) {
            Bolt11TagName tagName = tag.tagName();
            if (tagName == Bolt11TagName.UNKNOWN) {
                throw new IllegalArgumentException("Unknown tag key: " + tagName.wireName());
            }
            List<Integer> words = encodeTag(tagName, tag.data(), network);
            if (tagName == Bolt11TagName.FEATURES && words.isEmpty()) {
                continue;
            }
            tagWords.add(tagName.code());
            List<Integer> lenWords = intBEToWords(words.size(), 5);
            List<Integer> paddedLen = new ArrayList<>();
            paddedLen.add(0);
            paddedLen.addAll(lenWords);
            if (paddedLen.size() > 2) {
                paddedLen = paddedLen.subList(paddedLen.size() - 2, paddedLen.size());
            }
            tagWords.addAll(paddedLen);
            tagWords.addAll(words);
        }

        List<Integer> dataWords = new ArrayList<>(timestampWords);
        dataWords.addAll(tagWords);
        return new UnsignedPayload(prefix, dataWords);
    }

    private static final int DEFAULT_EXPIRY = 3600;
    private static final int DEFAULT_CLTV_EXPIRY = 18;
    private static final String DEFAULT_DESCRIPTION = "";
    private static final Pattern HEX_EVEN_PATTERN = Pattern.compile("(?i)^[0-9a-f]*$");
    private static final Pattern HRP_NUMERIC_PATTERN = Pattern.compile("^\\d+$");
    private static final int MAX_PAYMENT_REQUEST_LENGTH = 16 * 1024;
    private static final BigInteger MAX_MILLISATS = new BigInteger("2100000000000000000");
    private static final BigInteger MILLISATS_PER_BTC = BigInteger.valueOf(100_000_000_000L);
    private static final BigInteger MILLISATS_PER_MILLIBTC = BigInteger.valueOf(100_000_000L);
    private static final BigInteger MILLISATS_PER_MICROBTC = BigInteger.valueOf(100_000L);
    private static final BigInteger MILLISATS_PER_NANOBTC = BigInteger.valueOf(100L);
    private static final BigInteger PICOBTC_PER_MILLISATS = BigInteger.TEN;
    private static final BigInteger MAX_ROUTE_FEE_BASE_MSAT = new BigInteger("4294967295");
    private static final BigInteger MAX_ROUTE_FEE_PROPORTIONAL_MILLIONTHS = new BigInteger("4294967295");
    private static final long MAX_ROUTE_CLTV_EXPIRY_DELTA = 65535L;
    private static final int PAYMENT_HASH_LENGTH = 32;
    private static final int PAYMENT_SECRET_LENGTH = 32;
    private static final int DESCRIPTION_HASH_LENGTH = 32;
    private static final int PAYEE_PUBKEY_LENGTH = 33;
    private static final int BASE58_FALLBACK_HASH_LENGTH = 20;
    private static final BigInteger CURVE_ORDER_HALF = new BigInteger(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        16
    );
    private static final Object SKIP_TAG = new Object();
    private static final long MAX_BOLT11_TIMESTAMP = (1L << 35) - 1;

    private static final List<Bolt11Feature> FEATURES_BY_REQUIRED_BIT = Arrays
        .stream(Bolt11Feature.values())
        .sorted(Comparator.comparingInt(Bolt11Feature::requiredBitIndex))
        .collect(Collectors.toList());

    public static final Bolt11NetworkType DEFAULT_NETWORK = Bolt11NetworkType.MAINNET;
    public static final Bolt11NetworkType TEST_NETWORK = Bolt11NetworkType.TESTNET;
    public static final Bolt11NetworkType SIGNET_NETWORK = Bolt11NetworkType.SIGNET;
    public static final Bolt11NetworkType REGTEST_NETWORK = Bolt11NetworkType.REGTEST;
    public static final Bolt11NetworkType SIM_NETWORK = Bolt11NetworkType.SIMNET;

    public static Bolt11Invoice encode(Bolt11Invoice inputData) throws Bech32Exception {
        return encode(inputData, true);
    }

    public static Bolt11Invoice encode(Bolt11Invoice inputData, boolean addDefaults) throws Bech32Exception {
        Bolt11Invoice data = inputData.copy();
        boolean canReconstruct = data.getSignature() != null && data.getRecoveryFlag() != null;

        Bolt11NetworkType coinTypeObj = data.getNetwork();
        if (coinTypeObj == null && !canReconstruct) {
            coinTypeObj = DEFAULT_NETWORK;
            data.setNetwork(coinTypeObj);
        } else if (coinTypeObj == null) {
            throw new IllegalArgumentException("Need network for proper payment request reconstruction");
        }

        if (data.getTimestamp() == null && !canReconstruct) {
            data.setTimestamp(Instant.now());
        } else if (data.getTimestamp() == null) {
            throw new IllegalArgumentException("Need timestamp for proper payment request reconstruction");
        }

        List<Bolt11Tag> tags = data.getTags();
        if (tags == null) {
            throw new IllegalArgumentException("Payment Requests need tags array");
        }

        validateNoDuplicateSingletonTags(tags);

        if (countTag(tags, Bolt11TagName.PAYMENT_HASH) != 1) {
            throw new IllegalArgumentException("Lightning Payment Request needs a payment hash");
        }

        if (countTag(tags, Bolt11TagName.PAYMENT_SECRET) != 1) {
            throw new IllegalArgumentException("Lightning Payment Request needs a payment secret");
        }

        int descriptionTagCount = countTag(tags, Bolt11TagName.DESCRIPTION);
        int purposeTagCount = countTag(tags, Bolt11TagName.DESCRIPTION_HASH);
        if (descriptionTagCount > 0 && purposeTagCount > 0) {
            throw new IllegalArgumentException("Payment request requires exactly one of description or description hash");
        }

        if (!tagsContainItem(tags, Bolt11TagName.DESCRIPTION) && !tagsContainItem(tags, Bolt11TagName.DESCRIPTION_HASH)) {
            if (addDefaults) {
                tags.add(Bolt11Tag.of(Bolt11TagName.DESCRIPTION, DEFAULT_DESCRIPTION));
            } else {
                throw new IllegalArgumentException("Payment request requires description or description hash");
            }
        }

        if (tagsContainItem(tags, Bolt11TagName.DESCRIPTION)) {
            byte[] desc = Objects.toString(tagsItems(tags, Bolt11TagName.DESCRIPTION), "").getBytes(StandardCharsets.UTF_8);
            if (desc.length > 639) {
                throw new IllegalArgumentException("Description is too long: Max length 639 bytes");
            }
        }

        if (!tagsContainItem(tags, Bolt11TagName.EXPIRY) && !canReconstruct && addDefaults) {
            tags.add(Bolt11Tag.of(Bolt11TagName.EXPIRY, DEFAULT_EXPIRY));
        }

        if (!tagsContainItem(tags, Bolt11TagName.MIN_FINAL_CLTV_EXPIRY) && !canReconstruct && addDefaults) {
            tags.add(Bolt11Tag.of(Bolt11TagName.MIN_FINAL_CLTV_EXPIRY, DEFAULT_CLTV_EXPIRY));
        }

        byte[] nodePublicKey = null;
        byte[] tagNodePublicKey = null;
        if (tagsContainItem(tags, Bolt11TagName.PAYEE_PUBKEY)) {
            tagNodePublicKey = hexToBuffer(tagsItems(tags, Bolt11TagName.PAYEE_PUBKEY));
            validatePubkey(tagNodePublicKey, "payee node key is not a valid compressed secp256k1 pubkey");
        }
        if (data.getPayeeNodeKey() != null) {
            nodePublicKey = hexToBuffer(data.getPayeeNodeKey());
            validatePubkey(nodePublicKey, "payeeNodeKey is not a valid compressed secp256k1 pubkey");
        }
        if (nodePublicKey != null && tagNodePublicKey != null && !Arrays.equals(nodePublicKey, tagNodePublicKey)) {
            throw new IllegalArgumentException("payeeNodeKey and tag payee node key do not match");
        }
        nodePublicKey = nodePublicKey != null ? nodePublicKey : tagNodePublicKey;
        if (nodePublicKey != null) {
            data.setPayeeNodeKey(NGEUtils.bytesToHex(nodePublicKey));
        }

        if (tagsContainItem(tags, Bolt11TagName.FALLBACK)) {
            for (Object fallbackData : tagsItemsAll(tags, Bolt11TagName.FALLBACK)) {
                Bolt11FallbackAddress addrData = coerceFallbackAddress(fallbackData);
                validateAndNormalizeFallbackAddress(addrData, coinTypeObj);
            }
        }

        if (tagsContainItem(tags, Bolt11TagName.ROUTE_HINTS)) {
            for (Object routingInfoData : tagsItemsAll(tags, Bolt11TagName.ROUTE_HINTS)) {
                List<Bolt11RoutingInfoRoute> routingInfo = coerceRoutingInfo(routingInfoData);
                for (Bolt11RoutingInfoRoute route : routingInfo) {
                    if (
                        route.getPubkey() == null ||
                        route.getShortChannelId() == null ||
                        route.getFeeBaseMsat() == null ||
                        route.getFeeProportionalMillionths() == null ||
                        route.getCltvExpiryDelta() == null
                    ) {
                        throw new IllegalArgumentException("Routing info is incomplete");
                    }
                    byte[] routePubkey = hexToBuffer(route.getPubkey());
                    validatePubkey(routePubkey, "Routing info pubkey is not a valid pubkey");
                    byte[] shortId = hexToBuffer(route.getShortChannelId());
                    if (shortId == null || shortId.length != 8) {
                        throw new IllegalArgumentException("Routing info short channel id must be 8 bytes");
                    }
                    if (!isIntegerNumber(route.getFeeBaseMsat())) {
                        throw new IllegalArgumentException("Routing info fee base msat is not an integer");
                    }
                    if (
                        requireInteger(route.getFeeBaseMsat(), "Routing info fee base msat is not an integer")
                            .compareTo(MAX_ROUTE_FEE_BASE_MSAT) >
                        0
                    ) {
                        throw new IllegalArgumentException("Routing info fee base msat is out of range");
                    }
                    if (!isIntegerNumber(route.getFeeProportionalMillionths())) {
                        throw new IllegalArgumentException("Routing info fee proportional millionths is not an integer");
                    }
                    if (
                        requireInteger(
                            route.getFeeProportionalMillionths(),
                            "Routing info fee proportional millionths is not an integer"
                        )
                            .compareTo(MAX_ROUTE_FEE_PROPORTIONAL_MILLIONTHS) >
                        0
                    ) {
                        throw new IllegalArgumentException("Routing info fee proportional millionths is out of range");
                    }
                    if (!isIntegerNumber(route.getCltvExpiryDelta())) {
                        throw new IllegalArgumentException("Routing info cltv expiry delta is not an integer");
                    }
                    if (
                        NGEUtils.safeLong(requireInteger(route.getCltvExpiryDelta(), "Value is not an integer")) >
                        MAX_ROUTE_CLTV_EXPIRY_DELTA
                    ) {
                        throw new IllegalArgumentException("Routing info cltv expiry delta is out of range");
                    }
                }
            }
        }

        String prefix = "ln" + coinTypeObj.bech32();

        String hrpString;
        if (data.getMillisatoshis() != null && data.getSatoshis() != null) {
            hrpString = millisatToHrp(data.getMillisatoshis());
            String hrpStringSat = satToHrp(data.getSatoshis());
            if (!Objects.equals(hrpString, hrpStringSat)) {
                throw new IllegalArgumentException("satoshis and millisatoshis do not match");
            }
        } else if (data.getMillisatoshis() != null) {
            hrpString = millisatToHrp(data.getMillisatoshis());
        } else if (data.getSatoshis() != null) {
            hrpString = satToHrp(data.getSatoshis());
        } else {
            hrpString = "";
        }
        prefix += hrpString;

        long ts = data.getTimestamp().getEpochSecond();
        if (ts < 0 || ts > MAX_BOLT11_TIMESTAMP) {
            throw new IllegalArgumentException("Timestamp is out of range for BOLT11");
        }
        List<Integer> timestampWords = intBEToWords(ts, 5);
        while (timestampWords.size() < 7) {
            timestampWords.add(0, 0);
        }

        List<Integer> tagWords = new ArrayList<>();
        for (Bolt11Tag tag : tags) {
            Bolt11TagName tagName = tag.tagName();
            boolean known = tagName != Bolt11TagName.UNKNOWN;
            if (!known && !canReconstruct) {
                throw new IllegalArgumentException("Unknown tag key: " + tagName.wireName());
            }

            if (known) {
                validateKnownTagData(tagName, tag.data());
            }

            List<Integer> words;
            if (tagName != Bolt11TagName.UNKNOWN) {
                words = encodeTag(tagName, tag.data(), coinTypeObj);
                // BOLT11 requires omitting field 9 entirely when feature bits are all zero.
                if (tagName == Bolt11TagName.FEATURES && words.isEmpty()) {
                    continue;
                }
                tagWords.add(tagName.code());
            } else {
                Bolt11UnknownTagData result = unknownEncoder(coerceUnknownTagData(tag.data()));
                tagWords.add(result.getTagCode());
                ByteBuffer decoded = Bech32.bech32Decode(
                    result.getWords(),
                    -1,
                    new Bech32ChecksumVariant(),
                    Bech32.DataFormat.BITS_5
                );
                words = Bolt11WireUtils.unsignedByteBufferToList(decoded);
            }

            List<Integer> lenWords = intBEToWords(words.size(), 5);
            List<Integer> paddedLen = new ArrayList<>();
            paddedLen.add(0);
            paddedLen.addAll(lenWords);
            if (paddedLen.size() > 2) {
                paddedLen = paddedLen.subList(paddedLen.size() - 2, paddedLen.size());
            }
            tagWords.addAll(paddedLen);
            tagWords.addAll(words);
        }

        List<Integer> dataWords = new ArrayList<>(timestampWords);
        dataWords.addAll(tagWords);

        byte[] toSign = concat(
            prefix.getBytes(StandardCharsets.UTF_8),
            Bolt11WireUtils.convertBitsToBytes(dataWords, 5, 8, true)
        );
        byte[] payReqHash = sha256(toSign);

        List<Integer> sigWords = null;
        if (canReconstruct) {
            if (nodePublicKey != null) {
                byte[] signature = hexToBuffer(data.getSignature());
                int recoveryFlag = data.getRecoveryFlag();
                byte[] recoveredPubkey = NGEPlatform.get().secp256k1RecoverPublicKey(payReqHash, signature, recoveryFlag, true);
                if (!Arrays.equals(nodePublicKey, recoveredPubkey)) {
                    throw new IllegalArgumentException(
                        "Signature, message, and recoveryID did not produce the same pubkey as payeeNodeKey"
                    );
                }
                sigWords = hexToWord(NGEUtils.bytesToHex(signature) + "0" + recoveryFlag);
            } else {
                throw new IllegalArgumentException(
                    "Reconstruction with signature and recoveryID requires payeeNodeKey to verify correctness of input data."
                );
            }
        }

        if (sigWords != null) {
            dataWords.addAll(sigWords);
        }

        if (tagsContainItem(tags, Bolt11TagName.EXPIRY)) {
            long timeExpireDate =
                ts + NGEUtils.safeLong(requireInteger(tagsItems(tags, Bolt11TagName.EXPIRY), "Value is not an integer"));
            data.setTimeExpireDate(timeExpireDate);
        }

        data.setComplete(sigWords != null);
        data.setPaymentRequest(
            sigWords != null
                ? Bech32.bech32Encode(
                    prefix.getBytes(StandardCharsets.UTF_8),
                    ByteBuffer.wrap(Bolt11WireUtils.listToUnsignedByteArray(dataWords, 31, "Invalid bech32 data range")),
                    Bech32.DataFormat.BITS_5
                )
                : ""
        );
        data.setTags(tags);
        return data;
    }

    public static Bolt11Invoice sign(Bolt11Invoice inputPayReqObj, String inputPrivateKey) throws Bech32Exception {
        Bolt11Invoice payReqObj = inputPayReqObj.copy();
        byte[] privateKey = hexToBuffer(inputPrivateKey);

        if (
            Boolean.TRUE.equals(payReqObj.getComplete()) &&
            payReqObj.getPaymentRequest() != null &&
            !"".equals(payReqObj.getPaymentRequest())
        ) {
            return payReqObj;
        }

        if (privateKey == null || privateKey.length != 32 || !NGEPlatform.get().secp256k1PrivateKeyVerify(privateKey)) {
            throw new IllegalArgumentException("privateKey must be a 32 byte Buffer and valid private key");
        }

        // Canonicalize the unsigned payload from structured invoice fields so callers cannot
        // turn this API into an arbitrary-signature oracle by supplying crafted words/prefix.
        payReqObj = encode(payReqObj, false);

        List<Bolt11Tag> tags = payReqObj.getTags();

        byte[] nodePublicKey = null;
        byte[] tagNodePublicKey = null;

        if (tagsContainItem(tags, Bolt11TagName.PAYEE_PUBKEY)) {
            tagNodePublicKey = hexToBuffer(tagsItems(tags, Bolt11TagName.PAYEE_PUBKEY));
        }
        if (payReqObj.getPayeeNodeKey() != null) {
            nodePublicKey = hexToBuffer(payReqObj.getPayeeNodeKey());
        }

        if (nodePublicKey != null && tagNodePublicKey != null && !Arrays.equals(tagNodePublicKey, nodePublicKey)) {
            throw new IllegalArgumentException("payee node key tag and payeeNodeKey attribute must match");
        }

        nodePublicKey = tagNodePublicKey != null ? tagNodePublicKey : nodePublicKey;

        byte[] publicKey = NGEPlatform.get().secp256k1PublicKeyCreate(privateKey, true);

        if (nodePublicKey != null && !Arrays.equals(publicKey, nodePublicKey)) {
            throw new IllegalArgumentException("The private key given is not the private key of the node public key given");
        }

        UnsignedPayload ctx = buildUnsignedPayload(payReqObj);

        byte[] toSign = concat(ctx.prefix.getBytes(StandardCharsets.UTF_8), wordsToBuffer(ctx.dataWords, false));
        byte[] payReqHash = sha256(toSign);

        Secp256k1RecoverableSignature sigObj = NGEPlatform.get().secp256k1SignRecoverable(payReqHash, privateKey);
        List<Integer> sigWords = hexToWord(NGEUtils.bytesToHex(sigObj.getSignature64()) + "0" + sigObj.getRecoveryId());

        payReqObj.setPayeeNodeKey(NGEUtils.bytesToHex(publicKey));
        payReqObj.setSignature(NGEUtils.bytesToHex(sigObj.getSignature64()));
        payReqObj.setRecoveryFlag(sigObj.getRecoveryId());

        List<Integer> finalWords = new ArrayList<>(ctx.dataWords);
        finalWords.addAll(sigWords);

        payReqObj.setComplete(true);
        payReqObj.setPaymentRequest(
            Bech32.bech32Encode(
                ctx.prefix.getBytes(StandardCharsets.UTF_8),
                ByteBuffer.wrap(Bolt11WireUtils.listToUnsignedByteArray(finalWords, 31, "Invalid bech32 data range")),
                Bech32.DataFormat.BITS_5
            )
        );
        return payReqObj;
    }

    public static Bolt11Invoice decode(String paymentRequest) throws Bech32Exception {
        return decode(paymentRequest, (Bolt11NetworkType) null);
    }

    public static Bolt11Invoice decode(String paymentRequest, Bolt11NetworkType network) throws Bech32Exception {
        if (paymentRequest == null || paymentRequest.isEmpty()) {
            throw new IllegalArgumentException("Lightning Payment Request must be string");
        }
        if (paymentRequest.length() > MAX_PAYMENT_REQUEST_LENGTH) {
            throw new IllegalArgumentException("Lightning Payment Request is too long");
        }
        if (!paymentRequest.substring(0, Math.min(2, paymentRequest.length())).equalsIgnoreCase("ln")) {
            throw new IllegalArgumentException("Not a proper lightning payment request");
        }

        Bech32ChecksumVariant variant = new Bech32ChecksumVariant();
        ByteBuffer decodedData = Bech32.bech32Decode(paymentRequest, -1, variant, Bech32.DataFormat.BITS_5);
        paymentRequest = paymentRequest.toLowerCase(Locale.ROOT);
        String prefix = new String(Bech32.hrp(paymentRequest), StandardCharsets.UTF_8);
        List<Integer> words = new ArrayList<>(Bolt11WireUtils.unsignedByteBufferToList(decodedData));

        if (words.size() < 104) {
            throw new IllegalArgumentException("Signature is missing or incorrect");
        }

        List<Integer> sigWords = new ArrayList<>(words.subList(words.size() - 104, words.size()));
        List<Integer> wordsNoSig = new ArrayList<>(words.subList(0, words.size() - 104));
        words = new ArrayList<>(wordsNoSig);

        byte[] sigBufferAll = wordsToBuffer(sigWords, true);
        int recoveryFlag = sigBufferAll[sigBufferAll.length - 1] & 0xff;
        byte[] sigBuffer = Arrays.copyOf(sigBufferAll, sigBufferAll.length - 1);

        if (!(recoveryFlag >= 0 && recoveryFlag <= 3) || sigBuffer.length != 64) {
            throw new IllegalArgumentException("Signature is missing or incorrect");
        }

        Matcher prefixMatches = Pattern.compile("^ln(\\S+?)(\\d*)([a-zA-Z]?)$").matcher(prefix);
        boolean matched = prefixMatches.find();
        if (matched && (prefixMatches.group(2) == null || prefixMatches.group(2).isEmpty())) {
            prefixMatches = Pattern.compile("^ln(\\S+)$").matcher(prefix);
            matched = prefixMatches.find();
        }
        if (!matched) {
            throw new IllegalArgumentException("Not a proper lightning payment request");
        }

        String bech32Prefix = prefixMatches.group(1);

        Bolt11NetworkType coinNetwork = null;
        if (network == null) {
            coinNetwork = Bolt11NetworkType.fromBech32(bech32Prefix);
        } else {
            coinNetwork = network;
        }

        if (coinNetwork == null || !Objects.equals(coinNetwork.bech32(), bech32Prefix)) {
            throw new IllegalArgumentException("Unknown coin bech32 prefix");
        }

        String value = null;
        String divisor = "";
        if (prefixMatches.groupCount() >= 2) {
            value = prefixMatches.group(2);
        }
        if (prefixMatches.groupCount() >= 3 && prefixMatches.group(3) != null) {
            divisor = prefixMatches.group(3);
        }

        BigInteger satoshis;
        BigInteger millisatoshis;
        boolean removeSatoshis = false;

        if (value != null && !value.isEmpty()) {
            try {
                satoshis = hrpToSat(value + divisor);
            } catch (Exception e) {
                satoshis = null;
                removeSatoshis = true;
            }
            millisatoshis = hrpToMillisat(value + divisor);
        } else {
            satoshis = null;
            millisatoshis = null;
        }

        long timestamp = wordsToIntBE(words.subList(0, 7));
        words = new ArrayList<>(words.subList(7, words.size()));

        List<Bolt11Tag> tags = new ArrayList<>();

        while (!words.isEmpty()) {
            int tagCode = words.get(0);
            words = new ArrayList<>(words.subList(1, words.size()));
            if (words.size() < 2) {
                throw new IllegalArgumentException("Invalid payment request tag length");
            }

            Bolt11TagName tagName = Bolt11TagName.fromCode(tagCode);

            int tagLength = (int) wordsToIntBE(words.subList(0, 2));
            words = new ArrayList<>(words.subList(2, words.size()));
            if (tagLength < 0 || tagLength > words.size()) {
                throw new IllegalArgumentException("Invalid payment request tag length");
            }

            List<Integer> tagWords = new ArrayList<>(words.subList(0, tagLength));
            words = new ArrayList<>(words.subList(tagLength, words.size()));

            // Be strict on non-minimal representations for canonical integer/feature fields.
            if ((tagCode == 6 || tagCode == 24 || tagCode == 5) && hasLeadingZeroWord(tagWords)) {
                throw new IllegalArgumentException("Non-minimal field encoding");
            }

            Object parsed = parseTag(tagCode, tagWords, coinNetwork);
            if (parsed == SKIP_TAG) {
                continue;
            }

            tags.add(Bolt11Tag.of(tagName, parsed));
        }

        validateNoDuplicateSingletonTags(tags);
        if (countTag(tags, Bolt11TagName.PAYMENT_HASH) != 1) {
            throw new IllegalArgumentException("Lightning Payment Request needs a payment hash");
        }
        if (countTag(tags, Bolt11TagName.PAYMENT_SECRET) != 1) {
            throw new IllegalArgumentException("Lightning Payment Request needs a payment secret");
        }
        int descriptionTagCount = countTag(tags, Bolt11TagName.DESCRIPTION);
        int purposeTagCount = countTag(tags, Bolt11TagName.DESCRIPTION_HASH);
        if (descriptionTagCount + purposeTagCount != 1) {
            throw new IllegalArgumentException("Payment request requires exactly one of description or description hash");
        }
        if (tagsContainItem(tags, Bolt11TagName.FEATURES)) {
            Bolt11FeatureBits fB = coerceFeatureBits(tagsItems(tags, Bolt11TagName.FEATURES));
            if (fB.isExtraHasRequired()) {
                throw new IllegalArgumentException("Unknown required feature bits are not supported");
            }
            validateKnownFeatureDependencies(fB);
        }

        Long timeExpireDate = null;
        if (tagsContainItem(tags, Bolt11TagName.EXPIRY)) {
            timeExpireDate =
                timestamp + NGEUtils.safeLong(requireInteger(tagsItems(tags, Bolt11TagName.EXPIRY), "Value is not an integer"));
        }

        byte[] toSign = concat(
            prefix.getBytes(StandardCharsets.UTF_8),
            Bolt11WireUtils.convertBitsToBytes(wordsNoSig, 5, 8, true)
        );
        byte[] payReqHash = sha256(toSign);
        byte[] sigPubkey = NGEPlatform.get().secp256k1RecoverPublicKey(payReqHash, sigBuffer, recoveryFlag, true);

        if (tagsContainItem(tags, Bolt11TagName.PAYEE_PUBKEY)) {
            if (!isLowS(sigBuffer)) {
                throw new IllegalArgumentException("Signature is not compliant with low-S standard");
            }
            String taggedKey = Objects.toString(tagsItems(tags, Bolt11TagName.PAYEE_PUBKEY), "");
            if (!Objects.equals(taggedKey, NGEUtils.bytesToHex(sigPubkey))) {
                throw new IllegalArgumentException("Lightning Payment Request signature pubkey does not match payee pubkey");
            }
        }

        Bolt11Invoice finalResult = new Bolt11Invoice();
        finalResult.setPaymentRequest(paymentRequest);
        finalResult.setComplete(true);
        finalResult.setNetwork(coinNetwork);
        finalResult.setSatoshis(removeSatoshis ? null : satoshis);
        finalResult.setMillisatoshis(millisatoshis);
        finalResult.setTimestamp(timestamp);
        finalResult.setPayeeNodeKey(NGEUtils.bytesToHex(sigPubkey));
        finalResult.setSignature(NGEUtils.bytesToHex(sigBuffer));
        finalResult.setRecoveryFlag(recoveryFlag);
        finalResult.setTags(tags);

        if (timeExpireDate != null) {
            finalResult.setTimeExpireDate(timeExpireDate);
        }

        return finalResult;
    }

    public static String satToHrp(Object satoshis) {
        BigInteger sat = requireInteger(satoshis, "satoshis must be an integer");
        if (sat.signum() <= 0) {
            throw new IllegalArgumentException("satoshis must be positive");
        }
        return millisatToHrp(sat.multiply(BigInteger.valueOf(1000)));
    }

    public static String millisatToHrp(Object millisatoshis) {
        BigInteger msat = requireInteger(millisatoshis, "millisatoshis must be an integer");
        if (msat.signum() <= 0) {
            throw new IllegalArgumentException("millisatoshis must be positive");
        }
        String msatString = msat.toString();
        int len = msatString.length();

        if (len > 11 && msatString.endsWith("00000000000")) {
            return msat.divide(MILLISATS_PER_BTC) + "";
        } else if (len > 8 && msatString.endsWith("00000000")) {
            return msat.divide(MILLISATS_PER_MILLIBTC) + "m";
        } else if (len > 5 && msatString.endsWith("00000")) {
            return msat.divide(MILLISATS_PER_MICROBTC) + "u";
        } else if (len > 2 && msatString.endsWith("00")) {
            return msat.divide(MILLISATS_PER_NANOBTC) + "n";
        }
        return msat.multiply(PICOBTC_PER_MILLISATS) + "p";
    }

    public static BigInteger hrpToSat(String hrpString) {
        BigInteger msat = hrpToMillisat(hrpString);
        if (!msat.mod(BigInteger.valueOf(1000)).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Amount is outside of valid range");
        }
        return msat.divide(BigInteger.valueOf(1000));
    }

    public static BigInteger hrpToMillisat(String hrpString) {
        if (hrpString == null || hrpString.isEmpty()) {
            throw new IllegalArgumentException("Not a valid human readable amount");
        }
        String divisor = null;
        String value;
        if (hrpString.substring(hrpString.length() - 1).matches("^[munp]$")) {
            divisor = hrpString.substring(hrpString.length() - 1);
            value = hrpString.substring(0, hrpString.length() - 1);
        } else if (hrpString.substring(hrpString.length() - 1).matches("^[^munp0-9]$")) {
            throw new IllegalArgumentException("Not a valid multiplier for the amount");
        } else {
            value = hrpString;
        }

        if (!HRP_NUMERIC_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("Not a valid human readable amount");
        }

        BigInteger valueBN = new BigInteger(value);
        BigInteger millisatoshisBN = divisor != null
            ? valueBN.multiply(MILLISATS_PER_BTC).divide(divisorFactor(divisor))
            : valueBN.multiply(MILLISATS_PER_BTC);

        if (
            ("p".equals(divisor) && !valueBN.mod(BigInteger.TEN).equals(BigInteger.ZERO)) ||
            millisatoshisBN.compareTo(MAX_MILLISATS) > 0
        ) {
            throw new IllegalArgumentException("Amount is outside of valid range");
        }

        return millisatoshisBN;
    }

    private static BigInteger divisorFactor(String divisor) {
        switch (divisor) {
            case "m":
                return new BigInteger("1000");
            case "u":
                return new BigInteger("1000000");
            case "n":
                return new BigInteger("1000000000");
            case "p":
                return new BigInteger("1000000000000");
            default:
                throw new IllegalArgumentException("Not a valid multiplier for the amount");
        }
    }

    private static List<Integer> encodeTag(Bolt11TagName tagName, Object data, Bolt11NetworkType network) {
        switch (tagName) {
            case PAYMENT_HASH:
            case PAYMENT_SECRET:
            case PAYEE_PUBKEY:
                return hexToWord(data);
            case DESCRIPTION:
                return textToWord(Objects.toString(data, ""));
            case DESCRIPTION_HASH:
                return purposeCommitEncoder(data);
            case PAYMENT_METADATA:
                return hexToWord(data);
            case EXPIRY:
            case MIN_FINAL_CLTV_EXPIRY:
                return intBEToWords(NGEUtils.safeLong(requireInteger(data, "Value is not an integer")), 5);
            case FALLBACK:
                return fallbackAddressEncoder(coerceFallbackAddress(data));
            case ROUTE_HINTS:
                return routingInfoEncoder(coerceRoutingInfo(data));
            case FEATURES:
                return featureBitsEncoder(coerceFeatureBits(data));
            default:
                throw new IllegalArgumentException("Unknown tag key: " + tagName);
        }
    }

    private static Object parseTag(int tagCode, List<Integer> words, Bolt11NetworkType network) throws Bech32Exception {
        switch (tagCode) {
            case 1:
                return fixedLengthHex(words, PAYMENT_HASH_LENGTH, "payment hash");
            case 16:
                return fixedLengthHex(words, PAYMENT_SECRET_LENGTH, "payment secret");
            case 19:
                byte[] payeePubkey = wordsToBuffer(words, true);
                validatePubkey(payeePubkey, "payee node key is not a valid compressed secp256k1 pubkey");
                return NGEUtils.bytesToHex(payeePubkey);
            case 23:
                return fixedLengthHex(words, DESCRIPTION_HASH_LENGTH, "description hash");
            case 27:
                return NGEUtils.bytesToHex(wordsToBuffer(words, true));
            case 13:
                return new String(wordsToBuffer(words, true), StandardCharsets.UTF_8);
            case 6:
            case 24:
                return wordsToIntBE(words);
            case 9:
                return fallbackAddressParser(words, network);
            case 3:
                return routingInfoParser(words);
            case 5:
                return featureBitsParser(words);
            default:
                return getUnknownParser(tagCode, words);
        }
    }

    private static Bolt11UnknownTagData unknownEncoder(Bolt11UnknownTagData data) throws Bech32Exception {
        if (data.getWords() == null || data.getWords().isEmpty()) {
            throw new IllegalArgumentException("Unknown tag data is invalid");
        }
        return data;
    }

    private static Bolt11UnknownTagData getUnknownParser(int tagCode, List<Integer> words) throws Bech32EncodingException {
        return Bolt11UnknownTagData.of(
            tagCode,
            Bech32.bech32Encode(
                "unknown".getBytes(StandardCharsets.UTF_8),
                ByteBuffer.wrap(Bolt11WireUtils.listToUnsignedByteArray(words, 31, "Invalid bech32 data range")),
                Bech32.DataFormat.BITS_5
            )
        );
    }

    private static Object fallbackAddressParser(List<Integer> words, Bolt11NetworkType network) throws Bech32EncodingException {
        if (words == null || words.isEmpty()) {
            throw new IllegalArgumentException("Fallback address type is unknown");
        }
        int version = words.get(0);
        List<Integer> rest = words.subList(1, words.size());
        byte[] addressHash = wordsToBuffer(rest, true);

        String address = null;
        switch (version) {
            case 17:
                if (addressHash.length != BASE58_FALLBACK_HASH_LENGTH) {
                    throw new IllegalArgumentException("Fallback address length is invalid");
                }
                address = Base58Check.toBase58Check(addressHash, network.pubKeyHash());
                break;
            case 18:
                if (addressHash.length != BASE58_FALLBACK_HASH_LENGTH) {
                    throw new IllegalArgumentException("Fallback address length is invalid");
                }
                address = Base58Check.toBase58Check(addressHash, network.scriptHash());
                break;
            case 0:
            case 1:
                if (!network.validWitnessVersions().contains(version)) {
                    return SKIP_TAG;
                }
                validateSegwitProgram(addressHash, version);
                address = SegwitAddress.toBech32(addressHash, version, network.bech32());
                break;
            default:
                return SKIP_TAG;
        }

        Bolt11FallbackAddress out = new Bolt11FallbackAddress();
        out.setCode(version);
        out.setAddress(address);
        out.setAddressHash(NGEUtils.bytesToHex(addressHash));
        return out;
    }

    private static List<Integer> fallbackAddressEncoder(Bolt11FallbackAddress data) {
        List<Integer> out = new ArrayList<>();
        if (data.getCode() == null) {
            throw new IllegalArgumentException("Integer value out of range: null");
        }
        out.add(data.getCode().intValue());
        out.addAll(hexToWord(data.getAddressHash()));
        return out;
    }

    private static List<Bolt11RoutingInfoRoute> routingInfoParser(List<Integer> words) {
        List<Bolt11RoutingInfoRoute> routes = new ArrayList<>();
        byte[] routesBuffer = wordsToBuffer(words, true);
        if (routesBuffer.length % 51 != 0) {
            throw new IllegalArgumentException("Routing info length is invalid");
        }

        int offset = 0;
        while (offset < routesBuffer.length) {
            byte[] pubkey = Arrays.copyOfRange(routesBuffer, offset, offset + 33);
            byte[] shortChannelId = Arrays.copyOfRange(routesBuffer, offset + 33, offset + 41);
            byte[] feeBaseMsat = Arrays.copyOfRange(routesBuffer, offset + 41, offset + 45);
            byte[] feeProp = Arrays.copyOfRange(routesBuffer, offset + 45, offset + 49);
            byte[] cltv = Arrays.copyOfRange(routesBuffer, offset + 49, offset + 51);
            offset += 51;

            Bolt11RoutingInfoRoute route = new Bolt11RoutingInfoRoute();
            route.setPubkey(NGEUtils.bytesToHex(pubkey));
            route.setShortChannelId(NGEUtils.bytesToHex(shortChannelId));
            route.setFeeBaseMsat(new BigInteger(1, feeBaseMsat));
            route.setFeeProportionalMillionths(new BigInteger(1, feeProp));
            route.setCltvExpiryDelta(new BigInteger(1, cltv).longValueExact());
            routes.add(route);
        }

        return routes;
    }

    private static List<Integer> routingInfoEncoder(List<Bolt11RoutingInfoRoute> datas) {
        byte[] buffer = new byte[0];
        for (Bolt11RoutingInfoRoute data : datas) {
            ensureRoutingInfoRouteWithinWireLimits(data);
            buffer = concat(buffer, hexToBuffer(data.getPubkey()));
            buffer = concat(buffer, hexToBuffer(data.getShortChannelId()));
            buffer =
                concat(
                    buffer,
                    Bolt11WireUtils.padLeftUnsignedBytes(
                        intBEToWords(NGEUtils.safeLong(requireInteger(data.getFeeBaseMsat(), "Value is not an integer")), 8),
                        4
                    )
                );
            buffer =
                concat(
                    buffer,
                    Bolt11WireUtils.padLeftUnsignedBytes(
                        intBEToWords(
                            NGEUtils.safeLong(requireInteger(data.getFeeProportionalMillionths(), "Value is not an integer")),
                            8
                        ),
                        4
                    )
                );
            buffer =
                concat(
                    buffer,
                    Bolt11WireUtils.padLeftUnsignedBytes(
                        intBEToWords(
                            NGEUtils.safeLong(requireInteger(data.getCltvExpiryDelta(), "Value is not an integer")),
                            8
                        ),
                        2
                    )
                );
        }
        return toWords(buffer);
    }

    private static Bolt11FeatureBits featureBitsParser(List<Integer> words) {
        List<Boolean> bools = new ArrayList<>();
        List<Integer> rev = new ArrayList<>(words);
        Collections.reverse(rev);
        for (int word : rev) {
            bools.add((word & 0b1) != 0);
            bools.add((word & 0b10) != 0);
            bools.add((word & 0b100) != 0);
            bools.add((word & 0b1000) != 0);
            bools.add((word & 0b10000) != 0);
        }
        Bolt11FeatureBits featureBits = new Bolt11FeatureBits();
        featureBits.setWordLength(words.size());

        for (Bolt11Feature feature : FEATURES_BY_REQUIRED_BIT) {
            int requiredBitIndex = feature.requiredBitIndex();
            boolean required = requiredBitIndex < bools.size() && bools.get(requiredBitIndex);
            boolean supported = feature.supportedBitIndex() < bools.size() && bools.get(feature.supportedBitIndex());
            featureBits.setFeature(feature, Bolt11FeatureBits.FeatureFlag.of(required, supported));
        }

        int start = highestKnownFeatureBitIndex() + 1;
        featureBits.setExtraStartBit(start);

        if (bools.size() > start) {
            List<Boolean> extraBits = new ArrayList<>(bools.subList(start, bools.size()));
            boolean hasRequired = false;
            for (int i = 0; i < extraBits.size(); i++) {
                if (i % 2 == 0 && extraBits.get(i)) {
                    hasRequired = true;
                    break;
                }
            }
            featureBits.setExtraBits(extraBits);
            featureBits.setExtraHasRequired(hasRequired);
        } else {
            featureBits.setExtraBits(new ArrayList<>());
            featureBits.setExtraHasRequired(false);
        }

        return featureBits;
    }

    private static List<Integer> featureBitsEncoder(Bolt11FeatureBits featureBits) {
        Integer wordsLength = featureBits.getWordLength();

        List<Boolean> bools = new ArrayList<>();
        for (Bolt11Feature feature : FEATURES_BY_REQUIRED_BIT) {
            ensureBooleanCapacity(bools, feature.supportedBitIndex() + 1);
            Bolt11FeatureBits.FeatureFlag flag = featureBits.getFeature(feature);
            bools.set(feature.requiredBitIndex(), flag != null && flag.isRequired());
            bools.set(feature.supportedBitIndex(), flag != null && flag.isSupported());
        }

        while (!bools.isEmpty() && !bools.get(bools.size() - 1)) {
            bools.remove(bools.size() - 1);
        }
        while (bools.size() % 5 != 0) {
            bools.add(false);
        }

        List<Boolean> extraBits = featureBits.getExtraBits();
        if (extraBits != null && !extraBits.isEmpty()) {
            int startBit = featureBits.getExtraStartBit();
            while (bools.size() < startBit) {
                bools.add(false);
            }
            for (Boolean bit : extraBits) {
                bools.add(Boolean.TRUE.equals(bit));
            }
        }

        if (wordsLength != null && (bools.size() / 5) > wordsLength) {
            throw new IllegalArgumentException("word_length is too small to contain all featureBits");
        } else if (wordsLength == null) {
            wordsLength = (int) Math.ceil(bools.size() / 5.0);
        }

        List<Integer> out = new ArrayList<>();
        for (int index = 0; index < wordsLength; index++) {
            int base = index * 5;
            int w =
                (toBit(bools, base + 4) << 4) |
                (toBit(bools, base + 3) << 3) |
                (toBit(bools, base + 2) << 2) |
                (toBit(bools, base + 1) << 1) |
                (toBit(bools, base));
            out.add(w);
        }
        Collections.reverse(out);
        return out;
    }

    private static int toBit(List<Boolean> bools, int idx) {
        return idx < bools.size() && bools.get(idx) ? 1 : 0;
    }

    private static int highestKnownFeatureBitIndex() {
        int highest = -1;
        for (Bolt11Feature feature : Bolt11Feature.values()) {
            highest = Math.max(highest, feature.supportedBitIndex());
        }
        return highest;
    }

    private static void ensureBooleanCapacity(List<Boolean> bools, int size) {
        while (bools.size() < size) {
            bools.add(false);
        }
    }

    private static void ensureRoutingInfoRouteWithinWireLimits(Bolt11RoutingInfoRoute route) {
        BigInteger feeBaseMsat = requireInteger(route.getFeeBaseMsat(), "Routing info fee base msat is not an integer");
        if (feeBaseMsat.signum() < 0 || feeBaseMsat.compareTo(MAX_ROUTE_FEE_BASE_MSAT) > 0) {
            throw new IllegalArgumentException("Routing info fee base msat is out of range");
        }

        BigInteger feeProportional = requireInteger(
            route.getFeeProportionalMillionths(),
            "Routing info fee proportional millionths is not an integer"
        );
        if (feeProportional.signum() < 0 || feeProportional.compareTo(MAX_ROUTE_FEE_PROPORTIONAL_MILLIONTHS) > 0) {
            throw new IllegalArgumentException("Routing info fee proportional millionths is out of range");
        }

        long cltvExpiryDelta = NGEUtils.safeLong(requireInteger(route.getCltvExpiryDelta(), "Value is not an integer"));
        if (cltvExpiryDelta < 0 || cltvExpiryDelta > MAX_ROUTE_CLTV_EXPIRY_DELTA) {
            throw new IllegalArgumentException("Routing info cltv expiry delta is out of range");
        }
    }

    private static List<Integer> purposeCommitEncoder(Object data) {
        byte[] buffer;
        if (data instanceof String) {
            String s = (String) data;
            if (isStrictHex(s)) {
                buffer = hexToBuffer(s);
            } else {
                buffer = sha256(s.getBytes(StandardCharsets.UTF_8));
            }
        } else {
            throw new IllegalArgumentException("purpose or purpose commit must be a string or hex string");
        }
        if (buffer == null || buffer.length != DESCRIPTION_HASH_LENGTH) {
            throw new IllegalArgumentException("description hash must be 32 bytes");
        }
        return toWords(buffer);
    }

    private static Object tagsItems(List<Bolt11Tag> tags, Bolt11TagName tagName) {
        for (Bolt11Tag item : tags) {
            if (item.tagName() == tagName) {
                return item.data();
            }
        }
        return null;
    }

    private static List<Object> tagsItemsAll(List<Bolt11Tag> tags, Bolt11TagName tagName) {
        List<Object> out = new ArrayList<>();
        for (Bolt11Tag item : tags) {
            if (item.tagName() == tagName) {
                out.add(item.data());
            }
        }
        return out;
    }

    private static int countTag(List<Bolt11Tag> tags, Bolt11TagName tagName) {
        int count = 0;
        for (Bolt11Tag item : tags) {
            if (item.tagName() == tagName) {
                count++;
            }
        }
        return count;
    }

    private static boolean tagsContainItem(List<Bolt11Tag> tags, Bolt11TagName tagName) {
        return tagsItems(tags, tagName) != null;
    }

    private static BigInteger requireInteger(Object value, String errorMessage) {
        if (value == null) {
            throw new IllegalArgumentException(errorMessage);
        }
        if (value instanceof BigInteger) {
            return (BigInteger) value;
        }
        if (value instanceof BigDecimal) {
            try {
                return ((BigDecimal) value).toBigIntegerExact();
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException(errorMessage);
            }
        }
        if (value instanceof Number) {
            Number n = (Number) value;
            if (n instanceof Float || n instanceof Double) {
                double d = n.doubleValue();
                if (!Double.isFinite(d)) {
                    throw new IllegalArgumentException(errorMessage);
                }
                if (Math.floor(d) != d) {
                    throw new IllegalArgumentException(errorMessage);
                }
                if (d < Long.MIN_VALUE || d > Long.MAX_VALUE) {
                    throw new IllegalArgumentException(errorMessage);
                }
                return BigInteger.valueOf((long) d);
            }
            return BigInteger.valueOf(n.longValue());
        }
        if (value instanceof String && ((String) value).matches("^\\d+$")) {
            return new BigInteger((String) value);
        }
        throw new IllegalArgumentException(errorMessage);
    }

    private static boolean isIntegerNumber(Object value) {
        try {
            requireInteger(value, "x");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void validateNoDuplicateSingletonTags(List<Bolt11Tag> tags) {
        Set<Bolt11TagName> seen = new HashSet<>();
        for (Bolt11Tag tag : tags) {
            Bolt11TagName name = tag.tagName();
            if (!isSingletonTag(name)) {
                continue;
            }
            if (!seen.add(name)) {
                throw new IllegalArgumentException("Duplicate tag is not allowed: " + name.wireName());
            }
        }
    }

    private static boolean isSingletonTag(Bolt11TagName tagName) {
        switch (tagName) {
            case PAYMENT_HASH:
            case PAYMENT_SECRET:
            case DESCRIPTION:
            case PAYEE_PUBKEY:
            case DESCRIPTION_HASH:
            case EXPIRY:
            case MIN_FINAL_CLTV_EXPIRY:
            case PAYMENT_METADATA:
            case FEATURES:
                return true;
            default:
                return false;
        }
    }

    private static void validateKnownTagData(Bolt11TagName tagName, Object data) {
        switch (tagName) {
            case PAYMENT_HASH:
                validateFixedHexTagLength(data, PAYMENT_HASH_LENGTH, "payment hash");
                return;
            case PAYMENT_SECRET:
                validateFixedHexTagLength(data, PAYMENT_SECRET_LENGTH, "payment secret");
                return;
            case PAYEE_PUBKEY:
                validatePubkey(hexToBuffer(data), "payee node key is not a valid compressed secp256k1 pubkey");
                return;
            case DESCRIPTION_HASH:
                if (data instanceof String && isStrictHex((String) data)) {
                    validateFixedHexTagLength(data, DESCRIPTION_HASH_LENGTH, "description hash");
                }
                return;
            case PAYMENT_METADATA:
                if (hexToBuffer(data) == null) {
                    throw new IllegalArgumentException("Invalid hex string");
                }
                return;
            default:
                return;
        }
    }

    private static boolean hasLeadingZeroWord(List<Integer> words) {
        return words != null && words.size() > 1 && words.get(0) == 0;
    }

    private static void validateKnownFeatureDependencies(Bolt11FeatureBits featureBits) {
        Bolt11FeatureBits.FeatureFlag paymentSecret = featureBits.getFeatureOrDefault(Bolt11Feature.PAYMENT_SECRET);
        Bolt11FeatureBits.FeatureFlag varOnion = featureBits.getFeatureOrDefault(Bolt11Feature.VAR_ONION_OPTIN);
        Bolt11FeatureBits.FeatureFlag basicMpp = featureBits.getFeatureOrDefault(Bolt11Feature.BASIC_MPP);

        if ((paymentSecret.isRequired() || paymentSecret.isSupported()) && !(varOnion.isRequired() || varOnion.isSupported())) {
            throw new IllegalArgumentException("features are missing dependency: payment_secret requires var_onion_optin");
        }

        if ((basicMpp.isRequired() || basicMpp.isSupported()) && !(paymentSecret.isRequired() || paymentSecret.isSupported())) {
            throw new IllegalArgumentException("features are missing dependency: basic_mpp requires payment_secret");
        }
    }

    private static boolean isLowS(byte[] signature64) {
        if (signature64 == null || signature64.length != 64) {
            return false;
        }
        byte[] sBytes = Arrays.copyOfRange(signature64, 32, 64);
        BigInteger s = new BigInteger(1, sBytes);
        return s.compareTo(CURVE_ORDER_HALF) <= 0;
    }

    private static void validateFixedHexTagLength(Object data, int expectedLength, String tagName) {
        byte[] raw = hexToBuffer(data);
        if (raw == null || raw.length != expectedLength) {
            throw new IllegalArgumentException(tagName + " must be " + expectedLength + " bytes");
        }
    }

    private static String fixedLengthHex(List<Integer> words, int expectedLength, String tagName) {
        byte[] raw = wordsToBuffer(words, true);
        if (raw.length != expectedLength) {
            throw new IllegalArgumentException(tagName + " must be " + expectedLength + " bytes");
        }
        return NGEUtils.bytesToHex(raw);
    }

    private static void validatePubkey(byte[] pubkey, String errorMessage) {
        if (pubkey == null || pubkey.length != PAYEE_PUBKEY_LENGTH || !NGEPlatform.get().secp256k1PublicKeyVerify(pubkey)) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    private static void validateSegwitProgram(byte[] program, int version) {
        if (program == null || program.length < 2 || program.length > 40) {
            throw new IllegalArgumentException("Fallback address length is invalid");
        }
        if (version == 0 && program.length != 20 && program.length != 32) {
            throw new IllegalArgumentException("Fallback address length is invalid");
        }
    }

    private static void validateAndNormalizeFallbackAddress(Bolt11FallbackAddress data, Bolt11NetworkType network) {
        if (data == null) {
            throw new IllegalArgumentException("fallback data is invalid");
        }
        String address = data.getAddress();
        String addressHashHex = data.getAddressHash();
        Integer code = data.getCode();

        if (address != null) {
            byte[] parsedAddressHash;
            int parsedCode;
            SegwitAddress sw = null;
            try {
                sw = SegwitAddress.fromBech32(address);
            } catch (Bech32Exception | IllegalArgumentException ignored) {
                // Not a valid segwit/bech32 address, try legacy base58 below.
            }

            if (sw != null) {
                if (!network.validWitnessVersions().contains(sw.version())) {
                    throw new IllegalArgumentException("Fallback address witness version is unknown");
                }
                if (!Objects.equals(sw.prefix(), network.bech32())) {
                    throw new IllegalArgumentException(
                        "Fallback address network type does not match payment request network type"
                    );
                }
                validateSegwitProgram(sw.data(), sw.version());
                parsedAddressHash = sw.data();
                parsedCode = sw.version();
            } else {
                Base58Check.Decoded b58;
                try {
                    b58 = Base58Check.fromBase58Check(address);
                } catch (IllegalArgumentException ignored) {
                    throw new IllegalArgumentException("Fallback address type is unknown");
                }
                if (b58.version() != network.pubKeyHash() && b58.version() != network.scriptHash()) {
                    throw new IllegalArgumentException(
                        "Fallback address version (base58) is unknown or the network type is incorrect"
                    );
                }
                parsedAddressHash = b58.hash();
                if (parsedAddressHash.length != BASE58_FALLBACK_HASH_LENGTH) {
                    throw new IllegalArgumentException("Fallback address length is invalid");
                }
                parsedCode = b58.version() == network.pubKeyHash() ? 17 : 18;
            }

            if (code != null && code.intValue() != parsedCode) {
                throw new IllegalArgumentException("Fallback address code does not match fallback address");
            }

            if (addressHashHex != null) {
                byte[] providedHash = hexToBuffer(addressHashHex);
                if (providedHash == null || !Arrays.equals(providedHash, parsedAddressHash)) {
                    throw new IllegalArgumentException("Fallback address hash does not match fallback address");
                }
            }

            data.setCode(parsedCode);
            data.setAddressHash(NGEUtils.bytesToHex(parsedAddressHash));
            return;
        }

        if (code == null || addressHashHex == null) {
            throw new IllegalArgumentException("Fallback address requires either address or (code and addressHash)");
        }

        byte[] addressHash = hexToBuffer(addressHashHex);
        if (addressHash == null) {
            throw new IllegalArgumentException("Fallback address hash is invalid");
        }

        if (code == 17 || code == 18) {
            if (addressHash.length != BASE58_FALLBACK_HASH_LENGTH) {
                throw new IllegalArgumentException("Fallback address length is invalid");
            }
            return;
        }

        if (!network.validWitnessVersions().contains(code)) {
            throw new IllegalArgumentException("Fallback address witness version is unknown");
        }
        validateSegwitProgram(addressHash, code);
    }

    private static byte[] hexToBuffer(Object hex) {
        if (hex == null) {
            return null;
        }
        if (hex instanceof byte[]) {
            return Arrays.copyOf((byte[]) hex, ((byte[]) hex).length);
        }
        String s = Objects.toString(hex, "");
        if (!isStrictHex(s)) {
            return null;
        }
        return NGEUtils.hexToByteArray(s);
    }

    private static List<Integer> hexToWord(Object hex) {
        byte[] buffer = hexToBuffer(hex);
        if (buffer == null) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        return toWords(buffer);
    }

    private static List<Integer> textToWord(String text) {
        return toWords(text.getBytes(StandardCharsets.UTF_8));
    }

    private static List<Integer> toWords(byte[] bytes) {
        return Bolt11WireUtils.convertBits(bytes, 8, 5, true);
    }

    private static List<Integer> intBEToWords(long intBE, int bits) {
        if (intBE < 0) {
            throw new IllegalArgumentException("Integer value must be non-negative");
        }
        List<Integer> words = new ArrayList<>();
        long value = intBE;
        if (value == 0) {
            words.add(0);
            return words;
        }
        int mask = (1 << bits) - 1;
        while (value > 0) {
            words.add((int) (value & mask));
            value = value / (1L << bits);
        }
        Collections.reverse(words);
        return words;
    }

    private static long wordsToIntBE(List<Integer> words) {
        long total = 0;
        for (int i = 0; i < words.size(); i++) {
            int word = words.get(i);
            if (word < 0 || word > 31) {
                throw new IllegalArgumentException("Word out of range");
            }
            total = (total * 32L) + word;
        }
        return total;
    }

    private static boolean isStrictHex(String s) {
        return s.length() % 2 == 0 && HEX_EVEN_PATTERN.matcher(s).matches();
    }

    private static byte[] wordsToBuffer(List<Integer> words, boolean trim) {
        byte[] buffer = Bolt11WireUtils.convertBitsToBytes(words, 5, 8, true);
        if (trim && (words.size() * 5) % 8 != 0 && buffer.length > 0) {
            return Arrays.copyOf(buffer, buffer.length - 1);
        }
        return buffer;
    }

    private static byte[] sha256(byte[] data) {
        return NGEPlatform.get().sha256(data);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static Bolt11FeatureBits coerceFeatureBits(Object obj) {
        if (obj instanceof Bolt11FeatureBits) {
            return (Bolt11FeatureBits) obj;
        }
        throw new IllegalArgumentException("features data is invalid");
    }

    private static Bolt11FallbackAddress coerceFallbackAddress(Object obj) {
        if (obj instanceof Bolt11FallbackAddress) {
            return (Bolt11FallbackAddress) obj;
        }
        throw new IllegalArgumentException("fallback data is invalid");
    }

    private static List<Bolt11RoutingInfoRoute> coerceRoutingInfo(Object obj) {
        if (obj == null) {
            return new ArrayList<>();
        }
        if (!(obj instanceof List)) {
            throw new IllegalArgumentException("route_hints data is invalid");
        }
        List<Bolt11RoutingInfoRoute> out = new ArrayList<>();
        for (Object item : (List<?>) obj) {
            if (item instanceof Bolt11RoutingInfoRoute) {
                out.add((Bolt11RoutingInfoRoute) item);
            } else {
                throw new IllegalArgumentException("route_hints data is invalid");
            }
        }
        return out;
    }

    private static Bolt11UnknownTagData coerceUnknownTagData(Object obj) {
        if (obj instanceof Bolt11UnknownTagData) {
            return (Bolt11UnknownTagData) obj;
        }
        throw new IllegalArgumentException("Unknown tag data is invalid");
    }
}
