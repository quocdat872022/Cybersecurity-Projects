# Custom Rules

`dlp-scan` can load detection rules from YAML files instead of
requiring Python. This lets you add organization- or
country-specific patterns (internal ID formats, regional national
ID numbers, internal ticket references, etc.) without touching the
scanner's source.

## Enabling it

Set `detection.custom_rules_dir` in your config file (default
`.dlp-scanner.yml`):

```yaml
detection:
  custom_rules_dir: "rules"
```

Every `*.yml` / `*.yaml` file directly under that directory is
loaded at startup. See `rules/examples/international_ids.yml` for a
worked example.

## Schema

```yaml
rules:
  - id: CUSTOM_BR_CPF                # required, must start with CUSTOM_
    name: "Brazilian CPF Number"     # required, human-readable
    pattern: '\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'   # required, Python regex
    base_score: 0.40                 # required, 0.0-1.0
    context_keywords: ["cpf", "cadastro"]      # optional, default []
    compliance: ["LGPD"]             # optional, default []
    validator: "mod11"               # optional, default: no validation
    severity_override: "high"        # optional: critical/high/medium/low
```

| Field                | Required | Notes                                                                 |
|-----------------------|----------|------------------------------------------------------------------------|
| `id`                  | yes      | Must match `CUSTOM_[A-Z0-9_]+`. Cannot collide with another rule id.   |
| `name`                | yes      | Shown in reports as the rule name.                                    |
| `pattern`             | yes      | Standard Python `re` syntax, max 500 characters.                      |
| `base_score`          | yes      | Starting confidence before context/checksum boosts, `0.0`-`1.0`.      |
| `context_keywords`    | no       | Words/phrases that boost confidence when found nearby (see context.py). |
| `compliance`          | no       | Free-form framework tags merged into the finding's compliance list.    |
| `validator`           | no       | Name of a built-in validator (see below), or omit for none.           |
| `severity_override`   | no       | Force a severity instead of deriving it from the final score.         |

## Why rule ids must start with `CUSTOM_`

The registry loads built-in rules first, then custom rules. Any
custom rule whose `id` matches a built-in rule id, or another
already-loaded custom rule, is rejected and logged
(`custom_rule_shadows_builtin` / `custom_rule_duplicate_id`) --
custom rules can only add, never override.

## Built-in validators

Reference these by name in the `validator` field; you don't need to
write Python to use them.

| Name     | Checks                                                                 |
|----------|--------------------------------------------------------------------------|
| `luhn`   | Luhn checksum (most payment card numbers).                              |
| `mod97`  | ISO 7064 MOD 97-10 (the algorithm IBAN numbers use).                     |
| `mod11`  | Generic mod-11 check-digit scheme. Good default for "some digits + a check digit" IDs, but not a substitute for a country-specific algorithm. |
| `none`   | Always passes -- rely on `base_score` + `context_keywords` only.        |

Unknown validator names fail that single rule at load time (logged
as `custom_rule_unknown_validator`); they don't abort the rest of
the file.

## Regex safety

Because rule patterns are user-supplied, every pattern is checked
before it's trusted:

1. **Static heuristic** -- patterns matching a nested-quantifier
   shape (`(a+)+`, `(\d*)*`, ...), the classic catastrophic
   backtracking pattern, are rejected immediately.
2. **Dynamic probe** -- surviving patterns are run against several
   adversarial strings in an isolated child process with a
   1-second wall-clock timeout. If a probe doesn't finish in time,
   the process is killed and the pattern is rejected.

A rejected pattern is logged and skipped; it does not stop the rest
of the rules in that file (or other files) from loading.

## Failure handling

Nothing about a bad custom rule crashes a scan:

- A malformed YAML file is logged (`custom_rules_file_unreadable`)
  and skipped.
- A rule entry that fails schema validation is logged
  (`custom_rule_schema_invalid`) and skipped.
- A rule with an unsafe pattern, an unknown validator, or a
  colliding id is logged and skipped.

Check your logs after adding rules to confirm they actually loaded
-- a successful startup logs `custom_rules_loaded` with the count.