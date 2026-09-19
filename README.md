# Log-Sani

Log-Sani is a local-only browser tool for sanitizing SOC timelines, logs, ticket notes, and other text before sharing it.

**Current version: v1.0.0**

## Use it

1. Extract the complete ZIP. Keep `index.html`, the JavaScript files, `styles.css`, and the `assets` folder together.
2. Open `index.html` in a modern browser.
3. Paste text and select **Sanitize text**.
4. Clearly sensitive values are masked automatically. Review uncertain values and choose whether to mask them.
5. To mask any additional word or phrase, highlight it in the original text and select **Mask selected text**.
6. To restore one masked value, select **Unmask** beside it in the **Masked values** table. Only that value is restored everywhere; the other masks stay in place.

No server, installation, build step, or internet connection is required.

See `USER_MANUAL.md` for complete usage instructions.

## Project files

- `index.html` — page structure and security policy
- `styles.css` — interface design
- `sanitizer-engine.js` — detection, masking, restoration, and self-tests
- `app.js` — interface behavior and local file handling
- `assets/log-sani-eye.webp` — local logo artwork
- `USER_MANUAL.md` — end-user instructions
- `SECURITY.md` — security design, limitations, and release notes
- `LICENSE` — MIT license

## What it masks

- RFC1918, loopback, link-local, and CGNAT IPv4 addresses
- IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), and loopback (`::1`) addresses
- Usernames, dotted names, complete standard emails such as `name@example.com`, defanged emails such as `name@example[.]com`, SIDs, and usernames reused in paths or elsewhere in the text
- International phone numbers with a `+` country prefix
- High-confidence single-line postal addresses containing a street number, postal code, city, and country
- NetBIOS account prefixes and configured client DNS domains
- Common API tokens, bearer tokens, JWTs, private keys, and secret-like key/value fields
- Selected review suggestions such as public IPs, unknown domains, hostnames, and contextual standalone usernames
- User-defined JavaScript regular-expression rules
- Any exact word or phrase manually selected in the original text

Account parts are pseudonymized separately. For example, `EUR\\analyst` becomes `<NETBIOS_1>\\<USER_1>`, and the same username later in `C:\\Users\\analyst` becomes `C:\\Users\\<USER_1>`.

By default, Log-Sani preserves timestamps, timeline formatting, ports, PIDs, MITRE technique IDs, process and file names, command lines, GUIDs, and hexadecimal hashes.

## Automatic detection and review

High-confidence values—internal IP addresses, account identities, complete emails, international phone numbers, postal addresses, SIDs, secrets, NetBIOS account prefixes, and configured client domains—are masked automatically.

Values that may be investigation evidence are not changed automatically. Public IP addresses, unknown domains, likely hostnames, and contextual standalone usernames appear under **Review suggestions**. Select only the values you want to hide, then choose **Mask selected**. Allowlisted IOCs do not appear as suggestions.

An email such as `jakub.kadasi@something.com` is masked completely as one `<EMAIL_n>` token. If `jakub.kadasi` also appears separately in the text, that standalone identity receives its own `<USER_n>` token. A dotted name with no supporting identity context is shown for review instead of being masked automatically.

Light-green tokens were masked automatically. Amber tokens were masked after being selected from the review list.

Review choices are remembered in the current tab. Running sanitization again automatically reapplies earlier **Mask selected** and **Ignore selected** decisions. Selecting **Clear everything** or closing the tab resets them.

Individual **Unmask** choices are also remembered in the current tab. Unmasking restores that original value everywhere in the sanitized result and removes it from the restore key while leaving every other masked value unchanged. Selecting **Clear everything** or closing the tab resets these choices.

## Privacy and security

- The Content Security Policy blocks network access and allows scripts, styles, and images only from the extracted local project folder.
- There is no `fetch`, XHR, WebSocket, beacon, analytics, or remote asset code.
- Input, output, mappings, and configuration are never written to browser storage or cookies.
- Everything remains in page memory and disappears when the tab closes or **Clear everything** is selected.
- Mapping/config files are created or read only after an explicit download/upload action.
- User-controlled log text and imported values are rendered with DOM text nodes, not HTML parsing.
- Imported files and configuration structures have size and count limits.

Downloaded mapping files contain original sensitive values and should be protected accordingly.

See `SECURITY.md` for the security model and limitations. Log-Sani reduces accidental disclosure but is not a substitute for reviewing the final output before sharing it.

## Restore and mappings

Sanitization creates a reversible in-memory mapping. To restore text during the same session, paste its tokenized form into the input pane and select **Restore original text**. Use **Save restore key** and **Open restore key** when restoration must happen in a later session.

The **Unmask** button in the **Masked values** table is different: it restores only the selected unique value, across all of its occurrences, without restoring the rest of the text.

## Custom rules

Custom rules are a JSON array:

```json
[
  {
    "name": "hostname",
    "regex": "\\b(?:srv|ws)-[a-z0-9-]{3,}\\b",
    "replacement": "<HOST_{n}>"
  }
]
```

Use `{n}` in the replacement to generate unique reversible tokens. Regular expressions use JavaScript syntax without surrounding slash characters. Optional JavaScript `flags` are supported; global matching is always enabled.

## Self-tests

Open **Optional: edit detection rules**, expand **Developer options**, and select **Run safety tests**. The built-in fixtures cover IPv4/IPv6 classification, automatic account masking, consistent path reuse, Windows and registry-path protection, built-in account protection, allowlisting, hash and filename false-positive protection, secrets, defanged emails, international phone numbers, postal addresses, individual unmasking, suggestions, custom rules, and restoration.

## License

MIT
