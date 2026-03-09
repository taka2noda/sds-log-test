# SDS Log Test

Datadog Sensitive Data Scanner (SDS) configuration for testing custom scanning rules, focusing on Japanese PII and payment card data.

## Scanning Groups

### `tis-sds-test`

| Property | Value |
|---|---|
| **Group ID** | `a46d92d5-4d4f-4085-a2c8-34e03ae56609` |
| **Status** | Enabled |
| **Log Filter** | `service:sds-test` |
| **Products** | Logs |

Contains 6 custom rules (see below).

---

### `sds-test` (reference)

| Property | Value |
|---|---|
| **Group ID** | `a17b57ad-ad65-4a27-9cd7-5a1734fa30db` |
| **Status** | Enabled |
| **Log Filter** | `service:sds-test` |
| **Products** | Logs |

Contains the 6 custom rules below + 77 standard library rules for international PII and payment cards.

---

## Custom Rules

These 6 rules are defined in [`sds_custom_rules.json`](./sds_custom_rules.json) and applied in both `tis-sds-test` and `sds-test` groups.

### 1. JP Phone Number Scanner

| Field | Value |
|---|---|
| **Priority** | 2 |
| **Tag** | `sensitive_data:custom` |
| **Replacement** | `[jp_phone_number]` |
| **Pattern** | `0\d{1,4}[-－]\d{1,4}[-－]\d{4}` |

Matches Japanese phone numbers using both ASCII hyphen (`-`) and full-width hyphen (`－`).

---

### 2. JP Postal Code Scanner

| Field | Value |
|---|---|
| **Priority** | 5 |
| **Tag** | `sensitive_data:custom` |
| **Replacement** | `[jp_postal_code]` |
| **Pattern** | `\b\d{3}-\d{4}\b` |

Matches Japanese postal codes (e.g., `123-4567`).

> **Note:** The pattern `\d{3}-\d{4}` can also match phone number fragments like `045-000-0000`. Use keyword filtering on fields like `zip` or `postal_code` to improve precision.

---

### 3. JP Address Scanner

| Field | Value |
|---|---|
| **Priority** | 5 |
| **Tag** | `sensitive_data:jp_address_scanner` |
| **Replacement** | `[jp_address]` |
| **Pattern** | Matches any of the 47 prefecture names followed by `[^"]*` |

Triggers on a Japanese prefecture name (e.g., `東京都`, `大阪府`) and captures everything up to the next JSON quote, effectively masking the full address string in JSON log payloads.

---

### 4. JP Name (Kanji) Scanner

| Field | Value |
|---|---|
| **Priority** | 5 |
| **Tag** | `sensitive_data:jp_name_kanji_scanner` |
| **Replacement** | `[jp_kanji]` |
| **Pattern** | `[\x{4E00}-\x{9FFF}]{1,4}\s?[\x{4E00}-\x{9FFF}]{1,4}` |

Matches 1–4 CJK Unified Ideograph characters, an optional space, followed by another 1–4 CJK characters. This covers typical Japanese family-name + given-name patterns in kanji.

> **Note:** This also matches kanji addresses (e.g., `京都府京都市下京区`). Use keyword filtering on name fields for more precise targeting.

---

### 5. JP Name (Kana) Scanner

| Field | Value |
|---|---|
| **Priority** | 5 |
| **Tag** | `sensitive_data:jp_name_kana_scanner` |
| **Replacement** | `[jp_hiragana_kana]` |
| **Pattern** | `[ぁ-ゟァ-ヿー]{2,}` |

Matches 2 or more consecutive hiragana or katakana characters (including the long vowel mark `ー`).

---

### 6. Credit Card PAN Scanner (whole)

| Field | Value |
|---|---|
| **Priority** | 5 |
| **Tag** | `sensitive_data:credit_card_pan_scanner_whole` |
| **Replacement** | `[card_number]` |
| **Pattern** | `\b\d{13,19}\b` |

Matches any 13–19 digit number as a PAN (Primary Account Number) candidate. Covers all major card brands (Visa, Mastercard, Amex, JCB, Diners, etc.) in their unseparated full-digit format.

---

### 7. CVV/CVC Scanner

| Field | Value |
|---|---|
| **Priority** | 1 |
| **Tag** | `sensitive_data:cvv` |
| **Replacement** | `[cvv]` |
| **Pattern** | `\b\d{3,4}\b` |
| **Keywords** | `cvv`, `cvc`, `cvv2`, `csc`, `securityCode`, `security_code`, `card_verification` |
| **Keyword window** | 30 characters |

Matches 3–4 digit numbers that appear within 30 characters of a card verification keyword. The keyword guard prevents false positives on unrelated short numbers (e.g., order quantities, port numbers).

---

## Files

| File | Description |
|---|---|
| `sds_custom_rules.json` | Exportable JSON of all 6 custom rules with full attributes for reuse via the Datadog SDS API |

## Re-applying Rules via API

To recreate these rules in a new scanning group, use the Datadog SDS API:

```
POST https://api.datadoghq.com/api/v2/sensitive-data-scanner/config/rules
```

Each rule in `sds_custom_rules.json` maps directly to the request body `data.attributes`. Set `data.relationships.group.data.id` to the target group ID and `meta.version` to the current configuration version.

See the [Datadog SDS API reference](https://docs.datadoghq.com/api/latest/sensitive-data-scanner/) for full documentation.
