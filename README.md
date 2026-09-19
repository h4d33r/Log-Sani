# Log-Sani

Log-Sani is a single-file, local-only browser tool for sanitizing SOC timelines, logs, ticket notes, and other text before sharing it.

## Use it

1. Download `index.html`.
2. Open it in a modern browser.
3. Add the client DNS and NetBIOS domains under **Rules and configuration**.
4. Paste text and select **Sanitize**.

No server, installation, build step, or internet connection is required.

## What it masks

- RFC1918, loopback, link-local, and CGNAT IPv4 addresses
- IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), and loopback (`::1`) addresses
- Usernames, email local parts, SIDs, and usernames reused in paths
- Configured DNS and NetBIOS client domains
- Common API tokens, bearer tokens, JWTs, private keys, and secret-like key/value fields
- Optional public IPs, except configured allowlisted IOCs
- User-defined JavaScript regular-expression rules

Account parts are pseudonymized separately. For example, `EUR\\analyst` becomes `<NETBIOS_1>\\<USER_1>`, and the same username later in `C:\\Users\\analyst` becomes `C:\\Users\\<USER_1>`.

By default, Log-Sani preserves timestamps, timeline formatting, ports, PIDs, MITRE technique IDs, process and file names, command lines, GUIDs, and hexadecimal hashes.

## Privacy and security

- The Content Security Policy blocks all network access and permits only inline CSS/JavaScript plus data images.
- There is no `fetch`, XHR, WebSocket, beacon, analytics, or remote asset code.
- Input, output, mappings, and configuration are never written to browser storage or cookies.
- Everything remains in page memory and disappears when the tab closes or **Clear all** is selected.
- Mapping/config files are created or read only after an explicit download/upload action.

Downloaded mapping files contain original sensitive values and should be protected accordingly.

## Restore and mappings

Sanitization creates a reversible in-memory mapping. To restore text during the same session, paste its tokenized form into the input pane and select **Restore**. Use **Download mapping** and **Load mapping** when restoration must happen in a later session.

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

Open **Rules and configuration** and select **Run self-tests**. The built-in fixtures cover numeric IPv4/IPv6 classification, component-level identity masking, consistent path reuse, allowlisting, hash false-positive protection, secret masking, custom rules, and restoration.

## License

MIT
