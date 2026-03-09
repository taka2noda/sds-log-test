# SDS Log Test

Datadog Sensitive Data Scanner (SDS) configuration for testing custom scanning rules, focusing on Japanese PII and payment card data.

## How to Use This Repo

### Prerequisites

```bash
export DD_API_KEY="your_api_key"
export DD_APPLICATION_KEY="your_application_key"
```

### Step 1 — Create a scanning group

```bash
python3 create_sds_group.py --name "my-group"
```

Creates a new SDS scanning group with the filter `service:sds-test`.
The output will print the `group_id` needed for the next step.

### Step 2 — Add scanning rules

```bash
python3 create_custom_rules.py --group-id <group-id>
```

Reads `sds_custom_rules.json` and adds all 8 rules to the group.
Edit `sds_custom_rules.json` to add, remove, or modify rules before running.

### Step 3 — Send test logs

```bash
python3 send_logs.py
```

Sends 6 pre-defined test log entries to Datadog (`service=sds-test`) covering Japanese PII and payment card scenarios.

### Step 4 — Validate results

```bash
python3 validate_logs.py
```

Fetches the latest logs from Datadog, deduplicates by `request_id`, and checks that:
- All sensitive data has been replaced by mask tokens
- No raw PII (names, phone numbers, addresses, card numbers, CVV, email) remains

Options:
```bash
python3 validate_logs.py --since now-10m   # look back further if needed
```

### (Optional) Clear keyword match conditions

Standard Datadog SDS rules include keyword proximity filters by default — a rule only fires when a specified keyword (e.g., `card`, `pan`, `ssn`) appears within N characters of the pattern match. This reduces false positives but may miss matches in logs where the field name differs.

To remove all keyword match conditions from every rule in a group:

```bash
# Preview changes first (no changes applied)
python3 clear_rule_keywords.py --group-name "my-group" --dry-run

# Apply
python3 clear_rule_keywords.py --group-name "my-group"
```

After clearing, rules will fire on any pattern match regardless of surrounding context. Re-run `send_logs.py` and `validate_logs.py` to confirm the result.

> **Note:** This is a one-way operation per run. To restore the original keywords, the rules must be recreated from scratch.

---

## Files

| File | Description |
|---|---|
| `create_sds_group.py` | Step 1: create a Datadog SDS scanning group |
| `create_custom_rules.py` | Step 2: add rules from `sds_custom_rules.json` to a group |
| `sds_custom_rules.json` | Rule definitions (8 rules) |
| `send_logs.py` | Step 3: send 6 test logs to Datadog |
| `validate_logs.py` | Step 4: validate SDS masking results |
| `clear_rule_keywords.py` | (Optional) clear keyword match conditions from all rules in a group |

---

## Scanning Rules

All 8 rules are defined in `sds_custom_rules.json`.

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

> **Note:** The pattern can also match phone number fragments like `045-000-0000`. Use keyword filtering on fields like `zip` or `postal_code` to improve precision.

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

Matches 1–4 CJK Unified Ideograph characters, an optional space, followed by another 1–4 CJK characters. Covers typical Japanese family-name + given-name patterns in kanji.

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

### 7. Standard Email Address Scanner

| Field | Value |
|---|---|
| **Priority** | 1 |
| **Tag** | `sensitive_data:email_address` |
| **Replacement** | `[email_address]` |
| **Type** | Standard library rule (`PuXiVTCkTHOtj0Yad1ppsw`) |

Uses the Datadog built-in email address pattern.

---

### 8. CVV/CVC Scanner

| Field | Value |
|---|---|
| **Priority** | 1 |
| **Tag** | `sensitive_data:cvv` |
| **Replacement** | `[cvv]` |
| **Pattern** | `\b\d{3,4}\b` |
| **Keywords** | `cvv`, `cvc`, `cvv2`, `csc`, `securityCode`, `security_code`, `card_verification` |
| **Keyword window** | 30 characters |

Matches 3–4 digit numbers that appear within 30 characters of a card verification keyword. The keyword guard prevents false positives on unrelated short numbers.
