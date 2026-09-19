# Log-Sani Security

## Security design

- The application is fully static and has no backend.
- All processing occurs in the current browser tab.
- There are no network APIs, analytics, external libraries, remote fonts, or remote images.
- A restrictive Content Security Policy blocks network connections and permits executable resources only from the extracted local folder.
- Trusted Types enforcement blocks common DOM HTML-injection sinks in supporting browsers.
- Log text and imported mapping values are displayed with `textContent` and DOM text nodes, not `innerHTML`.
- No input, mapping, configuration, or review decision is written to cookies, local storage, session storage, or IndexedDB.
- Local file reads require an explicit file selection. File sizes and imported configuration counts are limited.
- Downloaded filenames are fixed by the application and cannot be supplied by log content.

## Security review result

The release contains no detected network call, dynamic code execution, inline event handler, inline script, inline stylesheet, HTML-injection sink, browser-storage use, or third-party dependency. The sanitizer engine's built-in automated tests must all pass before packaging.

## Important limitations

- Log-Sani is a pattern-based sanitizer, not a DLP product. It can miss an unfamiliar sensitive format or produce a false positive.
- Always review the final sanitized output before sharing it.
- Restore-key files contain the original sensitive data in plain JSON. Store and transfer them as confidential material.
- Custom rules are regular expressions executed in the browser. Only import trusted configuration files, and avoid expressions with excessive backtracking.
- Browser extensions, endpoint malware, screen-capture tools, or a compromised browser can still access text displayed in the tab.
- If the files are hosted on a website, loading the application contacts that hosting server. Sanitized log content still remains local unless the code is modified.

## Public-release checklist

1. Distribute the complete ZIP without removing or renaming required files.
2. Run **Developer options → Run safety tests** and confirm every test passes.
3. Review source changes for new network APIs, remote URLs, HTML-rendering sinks, and storage APIs.
4. Publish checksums for release ZIPs when distributing them outside a trusted channel.
5. Use a private security advisory process for vulnerability reports rather than asking reporters to post sensitive details publicly.
