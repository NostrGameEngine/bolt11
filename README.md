# bolt11 for Java

Java library for BOLT11 invoice encode/decode/sign.

This project focuses on a strict BOLT11 implementation.

## Installation

```gradle
repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.ngengine:bolt11:<version>'
}
```

> [!TIP]
> As `<version>` use one of the versions listed in the [releases page](/releases) or `0.0.0-SNAPSHOT` for the latest snapshot.


Add the right [nge-platform](https://github.com/NostrGameEngine/nge-platforms) for your target platform [from maven central](https://central.sonatype.com/search?q=nge-platform&namespace=org.ngengine).
For example, for desktop:

```gradle
dependencies {
    // ...
    implementation 'org.ngengine:nge-platform-jvm:<version>' // note: this requires java 21+
    // ...
}
```
  

## Usage

### BOLT11 decode

```java
import java.time.Instant;
import org.ngengine.bolt11.Bolt11;
import org.ngengine.bolt11.Bolt11Invoice;

Bolt11Invoice decoded = Bolt11.decode(invoiceString);

String payee = decoded.getPayeeNodeKey();
Instant timestamp = decoded.getTimestamp();
```

### BOLT11 encode + sign

```java
import java.time.Instant;
import java.util.List;
import org.ngengine.bolt11.*;

Bolt11Invoice inv = new Bolt11Invoice();
inv.setNetwork(Bolt11.DEFAULT_NETWORK);
inv.setTimestamp(Instant.now());
inv.setMillisatoshis(new java.math.BigInteger("1000"));
inv.setTags(List.of(
    Bolt11Tag.of(Bolt11TagName.PAYMENT_HASH, "0001020304050607080900010203040506070809000102030405060708090102"),
    Bolt11Tag.of(Bolt11TagName.PAYMENT_SECRET, "1111111111111111111111111111111111111111111111111111111111111111"),
    Bolt11Tag.of(Bolt11TagName.DESCRIPTION, "coffee")
));

Bolt11Invoice encoded = Bolt11.encode(inv, false);
Bolt11Invoice signed = Bolt11.sign(encoded, "<32-byte-hex-private-key>");

String paymentRequest = signed.getPaymentRequest();
```

> [!TIP]
> `Bolt11Invoice` uses wrapper types (`Boolean`, `Integer`) for some fields so they can be unset (`null`) in partial states.
> - `complete`: may be `null` before encode/sign/decode sets it.
> - `recoveryFlag`: may be `null` when no signature has been attached or parsed.
> - `signature`, `paymentRequest`, `payeeNodeKey`: may be `null` until signing/decoding.


## Validation Behavior

The implementation is intentionally strict.

- Requires exactly one `payment_hash` (`p`).
- Requires exactly one `payment_secret` (`s`).
- Requires exactly one of `description` (`d`) or `purpose_commit_hash` (`h`).
- Rejects malformed fixed-size fields (`p`, `s`, `h`, `n`).
- Enforces signature checks and low-S rules when payee key tag is present.
- Enforces positive amount values and 35-bit timestamp bounds.
- Skips unknown fallback address versions while validating known ones.

