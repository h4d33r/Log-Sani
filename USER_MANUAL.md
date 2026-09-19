# Log-Sani User Manual

## 1. Start the application

1. Extract the entire `Log-Sani.zip` file.
2. Keep all extracted files and the `assets` folder together.
3. Double-click `index.html` to open it in a current version of Chrome, Edge, or Firefox.

Log-Sani runs locally in that browser tab. It does not require installation, a web server, or an internet connection.

## 2. Sanitize text

1. Paste the original log, alert, timeline, or ticket text into the left panel.
2. Select **Sanitize text**.
3. Read the sanitized result in the right panel.
4. Check **Review suggestions** for uncertain values.
5. Select the suggestions you want to hide and choose **Mask selected**. Use **Ignore selected** for values you intentionally want to preserve.
6. Review the **Masked values** table.
7. Select **Copy sanitized text** when the result is ready.

Always read the final result before sharing it. Automatic detection cannot understand every organization-specific name or data format.

## 3. Automatic masks and review suggestions

Log-Sani automatically masks high-confidence sensitive values, including:

- private, loopback, link-local, and CGNAT IP addresses;
- Windows `DOMAIN\username` accounts, SIDs, user-profile names, and supported standalone identities;
- complete normal and defanged email addresses;
- international phone numbers beginning with `+`;
- high-confidence postal-address lines;
- configured client domains and NetBIOS domains;
- common credentials, access tokens, bearer tokens, JWTs, and private keys.

Potential investigation evidence is placed in **Review suggestions** instead of being changed automatically. This includes public IP addresses, unknown domains, likely hostnames, and some standalone usernames.

Light-green tokens were masked automatically. Amber tokens were masked after a manual or review decision.

## 4. Mask any word or phrase

1. Highlight the exact word or phrase in the left input panel.
2. Select **Mask selected text**.

The selected value is replaced everywhere as `<MASK_n>`. Matching is case-sensitive and uses whole-word boundaries where appropriate.

## 5. Unmask one value

In the **Masked values** table, select **Unmask** beside the value you want to restore.

That unique value is restored in every occurrence. Other masked values stay masked. The choice is remembered while the tab remains open and is reapplied if you sanitize the text again.

Select **Clear everything** to reset masking, review, and unmask choices.

## 6. Save or restore sanitized text

Open **Advanced: open/save files and restore original text** to use these functions:

- **Open a local log file** reads a supported text file into the page.
- **Save sanitized text** downloads the current sanitized result.
- **Save restore key** downloads the token-to-original mapping.
- **Open restore key** loads a mapping saved during an earlier session.
- **Restore original text** restores tokenized text using the mapping currently held in the tab.

The restore-key JSON file contains the original sensitive values. Treat it as confidential and never send it with sanitized text.

## 7. Configure detection

Open **Optional: edit detection rules**.

- **Client domain list:** DNS domains that should be masked automatically. Enter one per line.
- **Client NetBIOS domain list:** account prefixes such as `EUR` in `EUR\username`.
- **IOC allowlist:** public IPs, domains, or CIDR ranges that should remain visible.
- **Custom rules:** advanced JavaScript regular expressions for organization-specific formats.

Use **Save these settings** to download a configuration file and **Open saved settings** to load it later.

Only load configuration and restore-key files that you created or trust. A badly designed custom regular expression can make processing slow or cause the tab to stop responding.

## 8. Built-in safety tests

Open **Optional: edit detection rules**, expand **Developer options**, and select **Run safety tests**. A release should show every test as `PASS` before use.

## 9. Troubleshooting

- If the page has no design or buttons do not work, extract the whole ZIP again and keep the files together.
- If copying is blocked, use **Save sanitized text** or allow clipboard access for the local page.
- If a value is missed, highlight it and use **Mask selected text**, or add a carefully tested custom rule.
- If legitimate evidence is masked, use **Unmask** for that row.
- If the tab becomes slow, reduce the input size and remove complex custom regular expressions.

## 10. Privacy checklist before sharing

1. Review every amber suggestion.
2. Search the result for client names, usernames, email addresses, phone numbers, and public IPs that may be sensitive.
3. Confirm that timestamps, process names, hashes, MITRE IDs, and other needed evidence are still present.
4. Copy or download only the sanitized result.
5. Keep the restore key private or delete it when it is no longer needed.
