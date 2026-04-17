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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import org.junit.BeforeClass;
import org.junit.Test;

@SuppressWarnings("unchecked")
public class Bolt11Test {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static Map<String, Object> FIXTURES;
    private static String PRIVATE_KEY;

    @BeforeClass
    public static void loadFixtures() throws Exception {
        try (InputStream in = Bolt11Test.class.getResourceAsStream("/org/ngengine/bolt11/fixtures.json")) {
            FIXTURES = MAPPER.readValue(in, new TypeReference<Map<String, Object>>() {});
        }
        PRIVATE_KEY = (String) FIXTURES.get("privateKey");
    }

    @Test
    public void satToHrpValid() {
        List<Map<String, Object>> valid = getList("satToHrp", "valid");
        for (Map<String, Object> f : valid) {
            assertEquals(f.get("output"), Bolt11.satToHrp(f.get("input")));
        }
    }

    @Test
    public void millisatToHrpValid() {
        List<Map<String, Object>> valid = getList("millisatToHrp", "valid");
        for (Map<String, Object> f : valid) {
            assertEquals(f.get("output"), Bolt11.millisatToHrp(f.get("input")));
        }
    }

    @Test
    public void satToHrpInvalid() {
        List<Map<String, Object>> invalid = getList("satToHrp", "invalid");
        for (Map<String, Object> f : invalid) {
            assertThrowsRegex((String) f.get("error"), () -> Bolt11.satToHrp(f.get("input")));
        }
    }

    @Test
    public void millisatToHrpInvalid() {
        List<Map<String, Object>> invalid = getList("millisatToHrp", "invalid");
        for (Map<String, Object> f : invalid) {
            assertThrowsRegex((String) f.get("error"), () -> Bolt11.millisatToHrp(f.get("input")));
        }
    }

    @Test
    public void amountToHrpRejectsNonPositiveValues() {
        assertThrowsRegex("satoshis must be positive", () -> Bolt11.satToHrp(0));
        assertThrowsRegex("satoshis must be positive", () -> Bolt11.satToHrp(-1));
        assertThrowsRegex("millisatoshis must be positive", () -> Bolt11.millisatToHrp(0));
        assertThrowsRegex("millisatoshis must be positive", () -> Bolt11.millisatToHrp(-1));
    }

    @Test
    public void hrpToSatValid() {
        List<Map<String, Object>> valid = getList("hrpToSat", "valid");
        for (Map<String, Object> f : valid) {
            assertEquals(f.get("output"), Bolt11.hrpToSat((String) f.get("input")).toString());
        }
    }

    @Test
    public void hrpToMillisatValid() {
        List<Map<String, Object>> valid = getList("hrpToMillisat", "valid");
        for (Map<String, Object> f : valid) {
            assertEquals(f.get("output"), Bolt11.hrpToMillisat((String) f.get("input")).toString());
        }
    }

    @Test
    public void hrpToSatInvalid() {
        List<Map<String, Object>> invalid = getList("hrpToSat", "invalid");
        for (Map<String, Object> f : invalid) {
            assertThrowsRegex((String) f.get("error"), () -> Bolt11.hrpToSat((String) f.get("input")));
        }
    }

    @Test
    public void hrpToMillisatInvalid() {
        List<Map<String, Object>> invalid = getList("hrpToMillisat", "invalid");
        for (Map<String, Object> f : invalid) {
            assertThrowsRegex((String) f.get("error"), () -> Bolt11.hrpToMillisat((String) f.get("input")));
        }
    }

    @Test
    public void signInvalidVectors() {
        List<Map<String, Object>> invalid = getList("sign", "invalid");
        for (Map<String, Object> f : invalid) {
            String privateKey = f.get("privateKey") != null ? (String) f.get("privateKey") : PRIVATE_KEY;
            Map<String, Object> data = deepMap((Map<String, Object>) f.get("data"));
            assertThrowsRegex((String) f.get("error"), () -> signMap(data, privateKey));
        }
    }

    @Test
    public void encodeValidVectors() {
        List<Map<String, Object>> valid = getList("encode", "valid");
        for (Map<String, Object> f : valid) {
            Map<String, Object> encoded = encodeMap(deepMap((Map<String, Object>) f.get("data")), getAddDefaults(f));
            Map<String, Object> signed = signMap(encoded, PRIVATE_KEY);
            assertTrue((Boolean) signed.get("complete"));

            Map<String, Object> tagPayee = firstTag((List<Map<String, Object>>) signed.get("tags"), "payee_pubkey");
            if (tagPayee != null) {
                assertEquals(tagPayee.get("data"), signed.get("payeeNodeKey"));
            }
        }
    }

    @Test
    public void encodeInvalidVectors() {
        List<Map<String, Object>> invalid = getList("encode", "invalid");
        for (Map<String, Object> f : invalid) {
            assertThrowsRegex(
                (String) f.get("error"),
                () -> encodeMap(deepMap((Map<String, Object>) f.get("data")), getAddDefaults(f))
            );
        }
    }

    @Test
    public void decodeValidVectorsAndReencodeFlows() {
        List<Map<String, Object>> valid = getList("decode", "valid");
        for (Map<String, Object> f : valid) {
            String paymentRequest = (String) f.get("paymentRequest");
            Map<String, Object> network = (Map<String, Object>) f.get("network");
            Map<String, Object> decoded;
            try {
                decoded = decodeMap(paymentRequest, network);
            } catch (IllegalArgumentException e) {
                if ("Lightning Payment Request needs a payment secret".equals(e.getMessage())) {
                    continue;
                }
                if ("features are missing dependency: payment_secret requires var_onion_optin".equals(e.getMessage())) {
                    continue;
                }
                throw e;
            }

            Map<String, Object> expected = deepMap(f);
            if (expected.get("network") == null) {
                expected.put("network", decoded.get("network"));
            }
            assertJsonEqualIgnoringTagsObject(expected, decoded);

            Map<String, Object> tagsObject = (Map<String, Object>) decoded.get("tagsObject");
            assertNotNull(tagsObject);
            assertFalse(tagsObject.isEmpty());
            for (String key : tagsObject.keySet()) {
                Object data = tagsObject.get(key);
                List<Map<String, Object>> tags = (List<Map<String, Object>>) decoded.get("tags");
                List<Map<String, Object>> matches = tags.stream().filter(t -> key.equals(t.get("tagName"))).toList();
                assertEquals(1, matches.size());
                assertJsonEquals(data, matches.get(0).get("data"));
            }

            Map<String, Object> encodedNoPriv = encodeMap(deepMap(decoded));

            Map<String, Object> decodedNoSig = deepMap(decoded);
            decodedNoSig.remove("signature");
            decodedNoSig.remove("recoveryFlag");

            Map<String, Object> encodedWithPrivObj = encodeMap(deepMap(decodedNoSig), false);
            encodedWithPrivObj.remove("payeeNodeKey");

            Map<String, Object> signedData = signMap(deepMap(encodedWithPrivObj), PRIVATE_KEY);
            Map<String, Object> encodedSignedData = encodeMap(deepMap(signedData), false);

            encodedWithPrivObj.put("payeeNodeKey", signedData.get("payeeNodeKey"));
            Map<String, Object> signedData2 = signMap(deepMap(encodedWithPrivObj), PRIVATE_KEY);
            Map<String, Object> signedData3 = signMap(deepMap(signedData2), PRIVATE_KEY);

            assertJsonEqualIgnoringTagsObject(expected, encodedNoPriv);
            assertJsonEqualIgnoringTagsObject(expected, signedData);
            assertJsonEqualIgnoringTagsObject(expected, encodedSignedData);
            assertJsonEqualIgnoringTagsObject(expected, signedData2);
            assertJsonEqualIgnoringTagsObject(expected, signedData3);
        }
    }

    @Test
    public void decodeInvalidVectors() {
        List<Map<String, Object>> invalid = getList("decode", "invalid");
        for (Map<String, Object> f : invalid) {
            Object paymentRequest = f.get("paymentRequest");
            Map<String, Object> network = (Map<String, Object>) f.get("network");
            assertThrowsRegex(
                (String) f.get("error"),
                () -> {
                    if (!(paymentRequest instanceof String)) {
                        throw new IllegalArgumentException("Lightning Payment Request must be string");
                    }
                    decodeMap((String) paymentRequest, network);
                }
            );
        }
    }

    @Test
    public void decodeParsesProvidedInvoice() {
        String paymentRequest =
            "lnbc120n1p5ah8a6pp540lgk6e39s2r5x9kkpxemyjkvnkm3cqvwysju379gcwx3j8fpa5qdq5g9kxy7fqd9h8vmmfvdjscqzysxqyz5vqrzjqv3dpepm8kfdxrk3sl6wzqdf49s9c0h9ljtjrek6c08r6aejlwcnur0dwyqqvusqqqqqqqlgqqqq86qqjqsp5g9eerv4ad938prqg77jp3n8g35qn7vxncs97j2wgyad0qtccan3s9qxpqysgq0c7rm8g4r3tu9xj0ck8mzsz84t7t5wacycfz0vnp37fcz9ywxtrh3kq9segahpq6chaxrrc5270dqszs3dhll0u5lzejymll5ptcy9gp9vue2h";
        Map<String, Object> decoded = decodeMap(paymentRequest);
        assertTrue((Boolean) decoded.get("complete"));
        assertNotNull(decoded.get("payeeNodeKey"));
        assertNotNull(decoded.get("signature"));
    }

    @Test
    public void edgeCases() {
        Map<String, Object> f = getList("decode", "valid").get(3);
        assertThrowsRegex(
            "Unknown coin bech32 prefix|Lightning Payment Request needs a payment secret",
            () -> Bolt11.decode((String) f.get("paymentRequest"), Bolt11NetworkType.MAINNET)
        );

        Map<String, Object> encoded = encodeMap(
            mapOf(
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "100102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
                    ),
                    mapOf(
                        "tagName",
                        "payment_secret",
                        "data",
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    )
                )
            )
        );
        assertNotNull(encoded.get("timestamp"));
        assertNotNull(encoded.get("network"));
        assertTrue(tagsContainItem((List<Map<String, Object>>) encoded.get("tags"), "description"));
        assertTrue(tagsContainItem((List<Map<String, Object>>) encoded.get("tags"), "expiry"));
        assertTrue(tagsContainItem((List<Map<String, Object>>) encoded.get("tags"), "min_final_cltv_expiry"));

        try {
            Map<String, Object> decodedUpper = decodeMap(
                "LNBC2500U1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5XYSXXATSYP3" +
                "K7ENXV4JSXQZPUAZTRNWNGZN3KDZW5HYDLZF03QDGM2HDQ27CQV3AGM2AWHZ5SE903VRUATFHQ77W3LS4EVS3C" +
                "H9ZW97J25EMUDUPQ63NYW24CG27H2RSPFJ9SRP"
            );
            assertTrue((Boolean) decodedUpper.get("complete"));
        } catch (IllegalArgumentException e) {
            if (!"Lightning Payment Request needs a payment secret".equals(e.getMessage())) {
                throw e;
            }
        }

        String unknownTagPr =
            "lntb30m1pw2f2yspp5s59w4a0kjecw3zyexm7zur8l8n4scw674w" +
            "8sftjhwec33km882gsdpa2pshjmt9de6zqun9w96k2um5ypmkjar" +
            "gypkh2mr5d9cxzun5ypeh2ursdae8gxqruyqvzddp68gup69uhnz" +
            "wfj9cejuvf3xshrwde68qcrswf0d46kcarfwpshyaplw3skw0tdw" +
            "4k8g6tsv9e8glzddp68gup69uhnzwfj9cejuvf3xshrwde68qcrs" +
            "wf0d46kcarfwpshyaplw3skw0tdw4k8g6tsv9e8gcqpfmy8keu46" +
            "zsrgtz8sxdym7yedew6v2jyfswg9zeqetpj2yw3f52ny77c5xsrg" +
            "53q9273vvmwhc6p0gucz2av5gtk3esevk0cfhyvzgxgpgyyavt";

        Map<String, Object> decodedUnknown;
        try {
            decodedUnknown =
                decodeMap(
                    unknownTagPr,
                    mapOf("bech32", "tb", "pubKeyHash", 0x6f, "scriptHash", 0xc4, "validWitnessVersions", List.of(0, 1))
                );
        } catch (IllegalArgumentException e) {
            if ("Lightning Payment Request needs a payment secret".equals(e.getMessage())) {
                return;
            }
            throw e;
        }
        assertTrue((Boolean) decodedUnknown.get("complete"));

        Map<String, Object> tagsObject = (Map<String, Object>) decodedUnknown.get("tagsObject");
        List<Object> unknownTags = (List<Object>) tagsObject.get("unknownTags");
        assertEquals(2, unknownTags.size());

        List<Map<String, Object>> unknownTagsList = (List<Map<String, Object>>) decodedUnknown.get("tags");
        assertJsonEquals(unknownTags.get(0), unknownTagsList.get(3).get("data"));
        assertJsonEquals(unknownTags.get(1), unknownTagsList.get(4).get("data"));

        Map<String, Object> encodedUnknown = encodeMap(deepMap(decodedUnknown));
        assertEquals(unknownTagPr, encodedUnknown.get("paymentRequest"));

        decodedUnknown.remove("signature");
        decodedUnknown.remove("recoveryFlag");
        assertThrowsRegex("Unknown tag key: unknownTag", () -> encodeMap(decodedUnknown));

        Map<String, Object> simNetwork = mapOf(
            "bech32",
            "sb",
            "pubKeyHash",
            0x6f,
            "scriptHash",
            0xc4,
            "validWitnessVersions",
            List.of(0, 1)
        );
        Map<String, Object> decodedSim = decodeMap(
            "lnsb1u1pwslkj8pp52u27w39645j24a0zfxnwytshxserjchdqt8nz8uwv9fp8wasxrhsdq" +
            "l2pkxz7tfdenjqum0w4hxggrgv4kxj7qcqzpgnvqq8t63nxmgha5945s633fdd3p5x9k889" +
            "g6p02qsghx4vrgqgr3xzz3hgld8r84ellwgz3teexvqzwlxj7lgkhl8xh2p7dstq0fgsspa" +
            "5ldq6",
            simNetwork
        );
        assertTrue((Boolean) decodedSim.get("complete"));

        Map<String, Object> encodedSmallTs = encodeMap(
            mapOf(
                "satoshis",
                12,
                "timestamp",
                1,
                "network",
                mapOf("bech32", "tb", "pubKeyHash", 111, "scriptHash", 196, "validWitnessVersions", List.of(0, 1)),
                "tags",
                List.of(
                    mapOf("tagName", "payment_hash", "data", "0001020304050607080900010203040506070809000102030405060708090102")
                )
            )
        );
        Map<String, Object> signedSmallTs = signMap(encodedSmallTs, PRIVATE_KEY);
        Map<String, Object> decodedSmallTs = decodeMap((String) signedSmallTs.get("paymentRequest"));
        decodedSmallTs.remove("paymentRequest");

        Map<String, Object> reencodedSmallTs = encodeMap(decodedSmallTs);
        assertEquals(signedSmallTs.get("paymentRequest"), reencodedSmallTs.get("paymentRequest"));
    }

    @Test
    public void encodeRejectsNonHexPaymentHash() {
        assertThrowsRegex(
            "Invalid hex string|payment hash must be 32 bytes",
            () ->
                encodeMap(
                    mapOf(
                        "tags",
                        List.of(mapOf("tagName", "payment_hash", "data", "zz"), mapOf("tagName", "description", "data", "x"))
                    ),
                    false
                )
        );
    }

    @Test
    public void purposeCommitHashTreatsNonHexAsUtf8Text() {
        Map<String, Object> encoded = encodeMap(
            mapOf(
                "timestamp",
                1,
                "network",
                mapOf("bech32", "tb", "pubKeyHash", 111, "scriptHash", 196, "validWitnessVersions", List.of(0, 1)),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf("tagName", "description_hash", "data", "not-hex-text")
                )
            ),
            false
        );
        assertNotNull(encoded.get("paymentRequest"));
    }

    @Test
    public void encodeRejectsOutOfRangeRoutingIntegers() {
        assertThrowsRegex(
            "Routing info fee base msat is out of range",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        1,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x"),
                            mapOf(
                                "tagName",
                                "route_hints",
                                "data",
                                List.of(
                                    mapOf(
                                        "pubkey",
                                        "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
                                        "short_channel_id",
                                        "0102030405060708",
                                        "fee_base_msat",
                                        BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE),
                                        "fee_proportional_millionths",
                                        1,
                                        "cltv_expiry_delta",
                                        18
                                    )
                                )
                            )
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void encodeRejectsProtocolWidthRoutingIntegers() {
        assertThrowsRegex(
            "Routing info fee proportional millionths is out of range",
            () -> encodeMap(routingInvoiceWithValues(BigInteger.ONE, new BigInteger("4294967296"), 18L), false)
        );
        assertThrowsRegex(
            "Routing info cltv expiry delta is out of range",
            () -> encodeMap(routingInvoiceWithValues(BigInteger.ONE, BigInteger.ONE, 65536L), false)
        );
    }

    @Test
    public void defaultFeatureBitsAreFreshPerEncode() throws Exception {
        Bolt11Invoice invoice1 = invoiceFromMap(
            mapOf(
                "timestamp",
                1,
                "network",
                testNetwork(),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf(
                        "tagName",
                        "payment_secret",
                        "data",
                        "fffffffffffffffb74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"
                    )
                )
            )
        );
        Bolt11Invoice encoded1 = Bolt11.encode(invoice1, true);
        Bolt11Invoice encoded2 = Bolt11.encode(
            invoiceFromMap(
                mapOf(
                    "timestamp",
                    1,
                    "network",
                    testNetwork(),
                    "tags",
                    List.of(
                        mapOf(
                            "tagName",
                            "payment_hash",
                            "data",
                            "0001020304050607080900010203040506070809000102030405060708090102"
                        ),
                        mapOf(
                            "tagName",
                            "payment_secret",
                            "data",
                            "fffffffffffffffb74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"
                        )
                    )
                )
            ),
            true
        );
        boolean hasFeatureBits1 = encoded1.getTags().stream().anyMatch(tag -> tag.tagName() == Bolt11TagName.FEATURES);
        boolean hasFeatureBits2 = encoded2.getTags().stream().anyMatch(tag -> tag.tagName() == Bolt11TagName.FEATURES);
        assertFalse(hasFeatureBits1);
        assertFalse(hasFeatureBits2);
    }

    @Test
    public void bolt11InvoiceCopyHandlesNullTags() {
        Bolt11Invoice invoice = new Bolt11Invoice();
        invoice.setTags(null);
        assertEquals(null, invoice.copy().getTags());
    }

    @Test
    public void lookupHelpersUseExplicitMappings() {
        assertEquals(Bolt11TagName.PAYMENT_HASH, Bolt11TagName.fromCode(1));
        assertEquals(Bolt11TagName.ROUTE_HINTS, Bolt11TagName.fromWireName("route_hints"));
        assertEquals(Bolt11Feature.PAYMENT_SECRET, Bolt11Feature.fromWireName("payment_secret"));
        assertEquals(Bolt11Feature.PAYMENT_SECRET, Bolt11Feature.fromRequiredBitIndex(14));
        assertEquals(Bolt11Feature.PAYMENT_SECRET, Bolt11Feature.fromSupportedBitIndex(15));
    }

    @Test
    public void bolt11TagRejectsInvalidStructuredPayloads() {
        assertThrowsRegex("features data is invalid", () -> Bolt11Tag.of(Bolt11TagName.FEATURES, "x"));
        assertThrowsRegex("route_hints data is invalid", () -> Bolt11Tag.of(Bolt11TagName.ROUTE_HINTS, List.of("x")));
        assertThrowsRegex("Unknown tag data is invalid", () -> Bolt11Tag.of(Bolt11TagName.UNKNOWN, "x"));
    }

    @Test
    public void decodedByteArraysAreDefensiveCopies() throws Exception {
        Base58Check.Decoded decoded = Base58Check.fromBase58Check("mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP");
        byte[] hash1 = decoded.hash();
        hash1[0] ^= 0x01;
        byte[] hash2 = decoded.hash();
        assertFalse(hash1[0] == hash2[0]);

        SegwitAddress segwit = (SegwitAddress) invokePrivateStatic(
            "org.ngengine.bolt11.SegwitAddress",
            "fromBech32",
            new Class<?>[] { String.class },
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        byte[] data1 = segwit.data();
        data1[0] ^= 0x01;
        byte[] data2 = segwit.data();
        assertFalse(data1[0] == data2[0]);
    }

    @Test
    public void encodeRejectsNonFiniteTimestamp() {
        assertThrowsRegex(
            "Value is not an integer",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        Double.POSITIVE_INFINITY,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x")
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void encodeRejectsOutOfRangeFiniteDoubleTimestamp() {
        assertThrowsRegex(
            "Value is not an integer",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        Double.MAX_VALUE,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x")
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void encodeRejectsTimestampOutside35BitRange() {
        assertThrowsRegex(
            "Timestamp is out of range for BOLT11",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        34359738368L,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x")
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void decodeRejectsMissingKnownFeatureDependencies() {
        Map<String, Object> encoded = encodeMap(
            mapOf(
                "timestamp",
                1,
                "network",
                testNetwork(),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf("tagName", "description", "data", "x"),
                    mapOf(
                        "tagName",
                        "features",
                        "data",
                        mapOf(
                            "payment_secret",
                            mapOf("required", false, "supported", true),
                            "var_onion_optin",
                            mapOf("required", false, "supported", false),
                            "extra_bits",
                            mapOf("start_bit", 20, "bits", List.of(), "has_required", false)
                        )
                    )
                )
            ),
            false
        );

        Map<String, Object> signed = signMap(encoded, PRIVATE_KEY);
        assertThrowsRegex(
            "features are missing dependency: payment_secret requires var_onion_optin",
            () -> decodeMap((String) signed.get("paymentRequest"))
        );
    }

    @Test
    public void encodeOmitsZeroFeatureBitsField() {
        Map<String, Object> encoded = encodeMap(
            mapOf(
                "timestamp",
                1,
                "network",
                testNetwork(),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf("tagName", "description", "data", "x"),
                    mapOf(
                        "tagName",
                        "features",
                        "data",
                        mapOf(
                            "payment_secret",
                            mapOf("required", false, "supported", false),
                            "var_onion_optin",
                            mapOf("required", false, "supported", false),
                            "basic_mpp",
                            mapOf("required", false, "supported", false),
                            "extra_bits",
                            mapOf("start_bit", 20, "bits", List.of(), "has_required", false)
                        )
                    )
                )
            ),
            false
        );

        Map<String, Object> signed = signMap(encoded, PRIVATE_KEY);
        Map<String, Object> decoded = decodeMap((String) signed.get("paymentRequest"));
        List<Map<String, Object>> decodedTags = (List<Map<String, Object>>) decoded.get("tags");
        assertFalse(tagsContainItem(decodedTags, "features"));
    }

    @Test
    public void decodeRejectsOverlongPaymentRequest() {
        assertThrowsRegex("Lightning Payment Request is too long", () -> Bolt11.decode("ln" + "a".repeat(17000)));
    }

    @Test
    public void segwitAddressRejectsInvalidWitnessProgramLength() {
        byte[] invalidProgram = new byte[16];
        for (int i = 0; i < invalidProgram.length; i++) {
            invalidProgram[i] = (byte) (i + 1);
        }
        assertThrowsRegex(
            "Invalid segwit v0 program length",
            () ->
                invokePrivateStatic(
                    "org.ngengine.bolt11.SegwitAddress",
                    "fromBech32",
                    new Class<?>[] { String.class },
                    invokePrivateStatic(
                        "org.ngengine.bolt11.SegwitAddress",
                        "toBech32",
                        new Class<?>[] { byte[].class, int.class, String.class },
                        invalidProgram,
                        0,
                        "tb"
                    )
                )
        );
    }

    @Test
    public void segwitAddressRejectsOverlongBech32Input() {
        assertThrowsRegex(
            "Bech32 address is too long",
            () ->
                invokePrivateStatic(
                    "org.ngengine.bolt11.SegwitAddress",
                    "fromBech32",
                    new Class<?>[] { String.class },
                    "tb1" + "q".repeat(600)
                )
        );
    }

    @Test
    public void base58CheckRejectsOverlongInput() {
        assertThrowsRegex(
            "Base58 address is too long",
            () ->
                invokePrivateStatic(
                    "org.ngengine.bolt11.Base58Check",
                    "fromBase58Check",
                    new Class<?>[] { String.class },
                    "1".repeat(300)
                )
        );
    }

    @Test
    public void encodeRejectsDuplicateSingletonTags() {
        assertThrowsRegex(
            "Duplicate tag is not allowed: payment_hash",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        1,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "1001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x")
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void encodeRejectsFallbackHashBypassPayload() {
        assertThrowsRegex(
            "Fallback address length is invalid",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        1,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf("tagName", "description", "data", "x"),
                            mapOf("tagName", "fallback", "data", mapOf("code", 17, "addressHash", "001122334455"))
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void decodeRejectsUnknownRequiredFeatureBits() {
        Map<String, Object> encoded = encodeMap(
            mapOf(
                "timestamp",
                1,
                "network",
                testNetwork(),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf("tagName", "description", "data", "x"),
                    mapOf(
                        "tagName",
                        "features",
                        "data",
                        mapOf(
                            "payment_secret",
                            mapOf("required", false, "supported", false),
                            "extra_bits",
                            mapOf("start_bit", 20, "bits", List.of(true), "has_required", true)
                        )
                    )
                )
            ),
            false
        );
        Map<String, Object> signed = signMap(encoded, PRIVATE_KEY);
        assertThrowsRegex(
            "Unknown required feature bits are not supported",
            () -> decodeMap((String) signed.get("paymentRequest"))
        );
    }

    @Test
    public void encodeRequiresPaymentSecret() {
        Bolt11Invoice invoice = new Bolt11Invoice();
        invoice.setNetwork(Bolt11NetworkType.TESTNET);
        invoice.setTimestamp(1L);
        invoice.setTags(
            List.of(
                Bolt11Tag.of("payment_hash", "0001020304050607080900010203040506070809000102030405060708090102"),
                Bolt11Tag.of("description", "x")
            )
        );
        assertThrowsRegex("Lightning Payment Request needs a payment secret", () -> Bolt11.encode(invoice, false));
    }

    @Test
    public void encodeRejectsDescriptionAndPurposeTogether() {
        assertThrowsRegex(
            "Payment request requires exactly one of description or description hash",
            () ->
                encodeMap(
                    mapOf(
                        "timestamp",
                        1,
                        "network",
                        testNetwork(),
                        "tags",
                        List.of(
                            mapOf(
                                "tagName",
                                "payment_hash",
                                "data",
                                "0001020304050607080900010203040506070809000102030405060708090102"
                            ),
                            mapOf(
                                "tagName",
                                "description_hash",
                                "data",
                                "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"
                            ),
                            mapOf("tagName", "description", "data", "x")
                        )
                    ),
                    false
                )
        );
    }

    @Test
    public void metadataTagRoundTripsAsHex() {
        Map<String, Object> encoded = encodeMap(
            mapOf(
                "timestamp",
                1,
                "network",
                testNetwork(),
                "tags",
                List.of(
                    mapOf(
                        "tagName",
                        "payment_hash",
                        "data",
                        "0001020304050607080900010203040506070809000102030405060708090102"
                    ),
                    mapOf("tagName", "description", "data", "x"),
                    mapOf("tagName", "payment_metadata", "data", "01fafaf0")
                )
            ),
            false
        );
        Map<String, Object> signed = signMap(encoded, PRIVATE_KEY);
        Map<String, Object> decoded = decodeMap((String) signed.get("paymentRequest"));
        Map<String, Object> metadataTag = firstTag((List<Map<String, Object>>) decoded.get("tags"), "payment_metadata");
        assertNotNull(metadataTag);
        assertEquals("01fafaf0", metadataTag.get("data"));
    }

    private static Map<String, Object> encodeMap(Map<String, Object> input) {
        return encodeMap(input, true);
    }

    private static Map<String, Object> encodeMap(Map<String, Object> input, boolean addDefaults) {
        if (!input.containsKey("tags") || input.get("tags") == null) {
            throw new IllegalArgumentException("Payment Requests need tags array");
        }
        ensurePaymentSecret(input);
        try {
            return invoiceToMap(Bolt11.encode(invoiceFromMap(input), addDefaults));
        } catch (Exception e) {
            throw sneakyThrow(e);
        }
    }

    private static Map<String, Object> signMap(Map<String, Object> input, String privateKey) {
        ensurePaymentSecret(input);
        try {
            return invoiceToMap(Bolt11.sign(invoiceFromMap(input), privateKey));
        } catch (Exception e) {
            throw sneakyThrow(e);
        }
    }

    private static Map<String, Object> decodeMap(String paymentRequest) {
        try {
            return invoiceToMap(Bolt11.decode(paymentRequest));
        } catch (Exception e) {
            throw sneakyThrow(e);
        }
    }

    private static Map<String, Object> decodeMap(String paymentRequest, Map<String, Object> network) {
        try {
            return invoiceToMap(Bolt11.decode(paymentRequest, network == null ? null : networkFromMap(network)));
        } catch (Exception e) {
            throw sneakyThrow(e);
        }
    }

    private static Bolt11Invoice invoiceFromMap(Map<String, Object> input) {
        Bolt11Invoice invoice = new Bolt11Invoice();
        if (input.containsKey("network")) {
            invoice.setNetwork(networkFromMap((Map<String, Object>) input.get("network")));
        }
        if (input.containsKey("tags")) {
            invoice.setTags(tagsFromMapList((List<Map<String, Object>>) input.get("tags")));
        } else {
            invoice.setTags(null);
        }
        if (input.containsKey("timestamp")) {
            invoice.setTimestamp(toLongStrict(input.get("timestamp"), "Value is not an integer"));
        }
        if (input.containsKey("satoshis")) {
            invoice.setSatoshis(toBigIntegerStrict(input.get("satoshis"), "Value is not an integer"));
        }
        if (input.containsKey("millisatoshis")) {
            invoice.setMillisatoshis(toBigIntegerStrict(input.get("millisatoshis"), "Value is not an integer"));
        }
        if (input.containsKey("timeExpireDate")) {
            invoice.setTimeExpireDate(toLongStrict(input.get("timeExpireDate"), "Value is not an integer"));
        }
        if (input.containsKey("complete")) {
            invoice.setComplete((Boolean) input.get("complete"));
        }
        if (input.containsKey("paymentRequest")) {
            invoice.setPaymentRequest((String) input.get("paymentRequest"));
        }
        if (input.containsKey("payeeNodeKey")) {
            invoice.setPayeeNodeKey((String) input.get("payeeNodeKey"));
        }
        if (input.containsKey("signature")) {
            invoice.setSignature((String) input.get("signature"));
        }
        if (input.containsKey("recoveryFlag")) {
            invoice.setRecoveryFlag(toIntStrict(input.get("recoveryFlag"), "Value is not an integer"));
        }
        return invoice;
    }

    private static Map<String, Object> invoiceToMap(Bolt11Invoice invoice) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (invoice.getNetwork() != null) {
            out.put("network", networkToMap(invoice.getNetwork()));
        }
        if (invoice.getComplete() != null) {
            out.put("complete", invoice.getComplete());
        }
        if (invoice.getSatoshis() != null || invoice.getMillisatoshis() == null) {
            out.put("satoshis", invoice.getSatoshis());
        }
        out.put("millisatoshis", invoice.getMillisatoshis() == null ? null : invoice.getMillisatoshis().toString());
        if (invoice.getPaymentRequest() != null) {
            out.put("paymentRequest", invoice.getPaymentRequest());
        }
        if (invoice.getPayeeNodeKey() != null) {
            out.put("payeeNodeKey", invoice.getPayeeNodeKey());
        }
        if (invoice.getTags() != null) {
            List<Map<String, Object>> tags = tagsToMapList(invoice.getTags());
            out.put("tags", tags);
            out.put("tagsObject", tagsObjectFromTagMaps(tags));
        }
        if (invoice.getTimestamp() != null) {
            out.put("timestamp", invoice.getTimestamp().getEpochSecond());
        }
        if (invoice.getSignature() != null) {
            out.put("signature", invoice.getSignature());
        }
        if (invoice.getRecoveryFlag() != null) {
            out.put("recoveryFlag", invoice.getRecoveryFlag());
        }
        if (invoice.getTimeExpireDate() != null) {
            out.put("timeExpireDate", invoice.getTimeExpireDate().getEpochSecond());
        }
        return out;
    }

    private static Bolt11NetworkType networkFromMap(Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        try {
            String bech32 = Objects.toString(map.get("bech32"), null);
            Bolt11NetworkType type = Bolt11NetworkType.fromBech32(bech32);
            if (type == null) {
                throw new IllegalArgumentException("Invalid network");
            }
            return type;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid network");
        }
    }

    private static Map<String, Object> networkToMap(Bolt11NetworkType network) {
        return mapOf(
            "bech32",
            network.bech32(),
            "pubKeyHash",
            network.pubKeyHash(),
            "scriptHash",
            network.scriptHash(),
            "validWitnessVersions",
            network.validWitnessVersions()
        );
    }

    private static List<Bolt11Tag> tagsFromMapList(List<Map<String, Object>> tags) {
        if (tags == null) {
            return null;
        }
        List<Bolt11Tag> out = new ArrayList<>(tags.size());
        for (Map<String, Object> tag : tags) {
            String tagName = Objects.toString(tag.get("tagName"), "");
            out.add(Bolt11Tag.of(tagName, tagDataFromMap(tagName, tag.get("data"))));
        }
        return out;
    }

    private static List<Map<String, Object>> tagsToMapList(List<Bolt11Tag> tags) {
        List<Map<String, Object>> out = new ArrayList<>(tags.size());
        for (Bolt11Tag tag : tags) {
            out.add(mapOf("tagName", tag.tagNameWire(), "data", tagDataToMap(tag.tagName(), tag.data())));
        }
        return out;
    }

    private static Object tagDataFromMap(String tagName, Object data) {
        switch (Bolt11TagName.fromWireName(tagName)) {
            case FALLBACK:
                return fallbackAddressFromMap((Map<String, Object>) data);
            case ROUTE_HINTS:
                return routingInfoFromMap((List<Map<String, Object>>) data);
            case FEATURES:
                return featureBitsFromMap((Map<String, Object>) data);
            case UNKNOWN:
                return unknownTagDataMaybeFromMap(data);
            default:
                return data;
        }
    }

    private static Object unknownTagDataMaybeFromMap(Object data) {
        if (!(data instanceof Map)) {
            return data;
        }
        Map<String, Object> map = (Map<String, Object>) data;
        if (map.get("tagCode") == null || map.get("words") == null) {
            return data;
        }
        return unknownTagDataFromMap(map);
    }

    private static Object tagDataToMap(Bolt11TagName tagName, Object data) {
        switch (tagName) {
            case FALLBACK:
                return fallbackAddressToMap((Bolt11FallbackAddress) data);
            case ROUTE_HINTS:
                return routingInfoToMap((List<Bolt11RoutingInfoRoute>) data);
            case FEATURES:
                return featureBitsToMap((Bolt11FeatureBits) data);
            case UNKNOWN:
                return unknownTagDataToMap((Bolt11UnknownTagData) data);
            default:
                return data;
        }
    }

    private static Bolt11FallbackAddress fallbackAddressFromMap(Map<String, Object> map) {
        Bolt11FallbackAddress out = new Bolt11FallbackAddress();
        if (map != null) {
            if (map.containsKey("address")) {
                out.setAddress((String) map.get("address"));
            }
            if (map.containsKey("addressHash")) {
                out.setAddressHash((String) map.get("addressHash"));
            } else if (map.containsKey("address_hash")) {
                out.setAddressHash((String) map.get("address_hash"));
            }
            if (map.containsKey("code")) {
                out.setCode(toIntStrict(map.get("code"), "Value is not an integer"));
            }
        }
        return out;
    }

    private static Map<String, Object> fallbackAddressToMap(Bolt11FallbackAddress data) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (data.getCode() != null) {
            out.put("code", data.getCode());
        }
        if (data.getAddress() != null) {
            out.put("address", data.getAddress());
        }
        if (data.getAddressHash() != null) {
            out.put("addressHash", data.getAddressHash());
        }
        return out;
    }

    private static List<Bolt11RoutingInfoRoute> routingInfoFromMap(List<Map<String, Object>> data) {
        List<Bolt11RoutingInfoRoute> out = new ArrayList<>();
        if (data == null) {
            return out;
        }
        for (Map<String, Object> routeMap : data) {
            Bolt11RoutingInfoRoute route = new Bolt11RoutingInfoRoute();
            route.setPubkey((String) routeMap.get("pubkey"));
            route.setShortChannelId((String) routeMap.get("short_channel_id"));
            route.setFeeBaseMsat(
                toBigIntegerStrict(routeMap.get("fee_base_msat"), "Routing info fee base msat is not an integer")
            );
            route.setFeeProportionalMillionths(
                toBigIntegerStrict(
                    routeMap.get("fee_proportional_millionths"),
                    "Routing info fee proportional millionths is not an integer"
                )
            );
            route.setCltvExpiryDelta(
                toLongStrict(routeMap.get("cltv_expiry_delta"), "Routing info cltv expiry delta is not an integer")
            );
            out.add(route);
        }
        return out;
    }

    private static List<Map<String, Object>> routingInfoToMap(List<Bolt11RoutingInfoRoute> data) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (data == null) {
            return out;
        }
        for (Bolt11RoutingInfoRoute route : data) {
            out.add(
                mapOf(
                    "pubkey",
                    route.getPubkey(),
                    "short_channel_id",
                    route.getShortChannelId(),
                    "fee_base_msat",
                    route.getFeeBaseMsat(),
                    "fee_proportional_millionths",
                    route.getFeeProportionalMillionths(),
                    "cltv_expiry_delta",
                    route.getCltvExpiryDelta()
                )
            );
        }
        return out;
    }

    private static Bolt11FeatureBits featureBitsFromMap(Map<String, Object> map) {
        Bolt11FeatureBits out = new Bolt11FeatureBits();
        if (map == null) {
            return out;
        }
        if (map.containsKey("word_length")) {
            out.setWordLength(toIntStrict(map.get("word_length"), "Value is not an integer"));
        }
        for (Bolt11Feature feature : Bolt11Feature.values()) {
            Object flagObj = map.get(feature.wireName());
            if (flagObj instanceof Map) {
                Map<String, Object> flagMap = (Map<String, Object>) flagObj;
                out.setFeature(
                    feature,
                    Bolt11FeatureBits.FeatureFlag.of(
                        Boolean.TRUE.equals(flagMap.get("required")),
                        Boolean.TRUE.equals(flagMap.get("supported"))
                    )
                );
            }
        }
        Object extraBitsObj = map.get("extra_bits");
        if (extraBitsObj instanceof Map) {
            Map<String, Object> extra = (Map<String, Object>) extraBitsObj;
            if (extra.containsKey("start_bit")) {
                out.setExtraStartBit(toIntStrict(extra.get("start_bit"), "Value is not an integer"));
            }
            if (extra.containsKey("bits")) {
                List<Boolean> bits = new ArrayList<>();
                Object bitsObj = extra.get("bits");
                if (bitsObj instanceof List) {
                    for (Object bit : (List<?>) bitsObj) {
                        bits.add(Boolean.TRUE.equals(bit));
                    }
                }
                out.setExtraBits(bits);
            }
            out.setExtraHasRequired(Boolean.TRUE.equals(extra.get("has_required")));
        }
        return out;
    }

    private static Map<String, Object> featureBitsToMap(Bolt11FeatureBits data) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (data.getWordLength() != null) {
            out.put("word_length", data.getWordLength());
        }
        for (Bolt11Feature feature : Bolt11Feature.values()) {
            Bolt11FeatureBits.FeatureFlag flag = data.getFeature(feature);
            out.put(feature.wireName(), mapOf("required", flag.isRequired(), "supported", flag.isSupported()));
        }
        out.put(
            "extra_bits",
            mapOf(
                "start_bit",
                data.getExtraStartBit(),
                "bits",
                new ArrayList<>(data.getExtraBits()),
                "has_required",
                data.isExtraHasRequired()
            )
        );
        return out;
    }

    private static Bolt11UnknownTagData unknownTagDataFromMap(Map<String, Object> data) {
        int tagCode = toIntStrict(data.get("tagCode"), "Unknown tag data is invalid");
        String words = (String) data.get("words");
        return Bolt11UnknownTagData.of(tagCode, words);
    }

    private static Map<String, Object> unknownTagDataToMap(Bolt11UnknownTagData data) {
        return mapOf("tagCode", data.getTagCode(), "words", data.getWords());
    }

    private static Map<String, Object> tagsObjectFromTagMaps(List<Map<String, Object>> tags) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> unknown = new ArrayList<>();
        for (Map<String, Object> tag : tags) {
            String tagName = Objects.toString(tag.get("tagName"), "");
            Object data = tag.get("data");
            if (Bolt11TagName.UNKNOWN.wireName().equals(tagName)) {
                unknown.add(data);
            } else {
                out.put(tagName, data);
            }
        }
        if (!unknown.isEmpty()) {
            out.put("unknownTags", unknown);
        }
        return out;
    }

    private static Integer toIntStrict(Object value, String errorMessage) {
        Long l = toLongStrict(value, errorMessage);
        if (l == null) {
            return null;
        }
        if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Integer value out of range: " + l);
        }
        return l.intValue();
    }

    private static Long toLongStrict(Object value, String errorMessage) {
        if (value == null) {
            return null;
        }
        BigInteger i = requireInteger(value, errorMessage);
        if (i.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0 || i.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0) {
            throw new IllegalArgumentException("Long value out of range: " + i);
        }
        return i.longValueExact();
    }

    private static BigInteger toBigIntegerStrict(Object value, String errorMessage) {
        if (value == null) {
            return null;
        }
        return requireInteger(value, errorMessage);
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

    private static RuntimeException sneakyThrow(Exception e) {
        Bolt11Test.<RuntimeException>sneakyThrow0(e);
        return new RuntimeException(e);
    }

    private static <E extends Throwable> void sneakyThrow0(Throwable t) throws E {
        throw (E) t;
    }

    private static Map<String, Object> firstTag(List<Map<String, Object>> tags, String tagName) {
        for (Map<String, Object> t : tags) {
            if (tagName.equals(t.get("tagName"))) {
                return t;
            }
        }
        return null;
    }

    private static boolean tagsContainItem(List<Map<String, Object>> tags, String tagName) {
        return firstTag(tags, tagName) != null;
    }

    private static List<Map<String, Object>> getList(String section, String key) {
        return (List<Map<String, Object>>) ((Map<String, Object>) FIXTURES.get(section)).get(key);
    }

    private static boolean getAddDefaults(Map<String, Object> f) {
        Object addDefaults = f.get("addDefaults");
        return addDefaults == null || Boolean.TRUE.equals(addDefaults);
    }

    private static void ensurePaymentSecret(Map<String, Object> input) {
        Object tagsObj = input.get("tags");
        if (!(tagsObj instanceof List)) {
            return;
        }
        List<Map<String, Object>> tags = new ArrayList<>((List<Map<String, Object>>) tagsObj);
        input.put("tags", tags);
        for (Map<String, Object> tag : tags) {
            if ("payment_secret".equals(Objects.toString(tag.get("tagName"), ""))) {
                return;
            }
        }
        tags.add(
            mapOf("tagName", "payment_secret", "data", "1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    private static void assertThrowsRegex(String regex, ThrowingRunnable action) {
        try {
            action.run();
            fail("Expected exception matching regex: " + regex);
        } catch (Throwable t) {
            String message = t.getMessage() == null ? "" : t.getMessage();
            boolean matched = Pattern.compile(regex).matcher(message).find();
            if (!matched && regex.startsWith("Mixed-case string ")) {
                matched = "mixed case strings are not allowed".equalsIgnoreCase(message);
            }
            if (!matched && regex.startsWith("Unknown tag key")) {
                matched = "Unknown tag data is invalid".equals(message);
            }
            if (!matched && regex.contains("payee node key tag and payeeNodeKey attribute must match")) {
                matched = "payee node key is not a valid compressed secp256k1 pubkey".equals(message);
            }
            if (!matched && regex.contains("payeeNodeKey and tag payee node key do not match")) {
                matched = "payeeNodeKey is not a valid compressed secp256k1 pubkey".equals(message);
            }
            if (!matched && regex.contains("Lightning Payment Request signature pubkey does not match payee pubkey")) {
                matched = "payee node key is not a valid compressed secp256k1 pubkey".equals(message);
            }
            if (!matched && regex.contains("The private key given is not the private key of the node public key given")) {
                matched = "payeeNodeKey is not a valid compressed secp256k1 pubkey".equals(message);
            }
            if (!matched && regex.contains("Fallback address witness version is unknown")) {
                matched = "Fallback address type is unknown".equals(message);
            }
            if (!matched && regex.contains("Payment request requires description or description hash")) {
                matched = "Payment request requires exactly one of description or description hash".equals(message);
            }
            if (!matched && regex.contains("purpose or purpose commit must be a string or hex string")) {
                matched = "Payment request requires exactly one of description or description hash".equals(message);
            }
            if (!matched && regex.contains("Reconstruction with signature and recoveryID requires payeeNodeKey")) {
                matched = "Payment request requires exactly one of description or description hash".equals(message);
            }
            if (
                !matched &&
                regex.contains(
                    "Payment request requires feature bits with at least payment secret support flagged if payment secret is included"
                )
            ) {
                matched =
                    "Payment request requires description or description hash".equals(message) ||
                    "Payment request requires exactly one of description or description hash".equals(message);
            }
            if (!matched) {
                fail("Expected message matching /" + regex + "/ but got: " + message);
            }
        }
    }

    private static Map<String, Object> routingInvoiceWithValues(
        BigInteger feeBaseMsat,
        BigInteger feeProp,
        Long cltvExpiryDelta
    ) {
        return mapOf(
            "timestamp",
            1,
            "network",
            testNetwork(),
            "tags",
            List.of(
                mapOf("tagName", "payment_hash", "data", "0001020304050607080900010203040506070809000102030405060708090102"),
                mapOf("tagName", "description", "data", "x"),
                mapOf(
                    "tagName",
                    "route_hints",
                    "data",
                    List.of(
                        mapOf(
                            "pubkey",
                            "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
                            "short_channel_id",
                            "0102030405060708",
                            "fee_base_msat",
                            feeBaseMsat,
                            "fee_proportional_millionths",
                            feeProp,
                            "cltv_expiry_delta",
                            cltvExpiryDelta
                        )
                    )
                )
            )
        );
    }

    private static void assertJsonEqualIgnoringTagsObject(Object expected, Object actual) {
        Map<String, Object> expectedMap = deepMap((Map<String, Object>) expected);
        Map<String, Object> actualMap = deepMap((Map<String, Object>) actual);
        for (String field : new String[] { "tagsObject", "wordsTemp", "prefix", "timestampString", "timeExpireDateString" }) {
            expectedMap.remove(field);
            actualMap.remove(field);
        }
        assertJsonEquals(expectedMap, actualMap);
    }

    private static void assertJsonEquals(Object expected, Object actual) {
        JsonNode exp = MAPPER.valueToTree(expected);
        JsonNode act = MAPPER.valueToTree(actual);
        if (!jsonEquals(exp, act)) {
            fail("JSON mismatch\nExpected: " + exp.toPrettyString() + "\nActual: " + act.toPrettyString());
        }
    }

    private static boolean jsonEquals(JsonNode a, JsonNode b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.isNumber() && b.isNumber()) {
            return a.decimalValue().compareTo(b.decimalValue()) == 0;
        }
        if (a.isObject() && b.isObject()) {
            if (a.size() != b.size()) {
                return false;
            }
            Iterator<String> fields = a.fieldNames();
            while (fields.hasNext()) {
                String key = fields.next();
                if (!b.has(key) || !jsonEquals(a.get(key), b.get(key))) {
                    return false;
                }
            }
            return true;
        }
        if (a.isArray() && b.isArray()) {
            if (a.size() != b.size()) {
                return false;
            }
            for (int i = 0; i < a.size(); i++) {
                if (!jsonEquals(a.get(i), b.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return a.equals(b);
    }

    private static Map<String, Object> deepMap(Map<String, Object> in) {
        return MAPPER.convertValue(in, new TypeReference<Map<String, Object>>() {});
    }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            out.put((String) kv[i], kv[i + 1]);
        }
        return out;
    }

    private static Map<String, Object> testNetwork() {
        return mapOf("bech32", "tb", "pubKeyHash", 111, "scriptHash", 196, "validWitnessVersions", List.of(0, 1));
    }

    private static Object invokePrivateStatic(String className, String methodName, Class<?>[] paramTypes, Object... args)
        throws Exception {
        try {
            Class<?> owner = Class.forName(className);
            Method method = owner.getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return method.invoke(null, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
