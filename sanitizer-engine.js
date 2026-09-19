  "use strict";

  /* Pure sanitization engine. It has no DOM, network, storage, or logging access. */
  const SanitizerEngine = (() => {
    const MAX_IMPORTED_MAPPINGS = 100000;
    const MAX_CONFIG_LIST_ITEMS = 5000;
    const MAX_CUSTOM_RULES = 50;
    const MAX_CUSTOM_REGEX_LENGTH = 1000;
    const CATEGORY_PREFIX = Object.freeze({
      internalIPs: "IP_INTERNAL",
      identities: "USER",
      emails: "EMAIL",
      phones: "PHONE",
      addresses: "ADDRESS",
      clientDomains: "DOMAIN",
      secrets: "SECRET",
      publicIPs: "IP_PUBLIC",
      manual: "MASK",
      custom: "CUSTOM"
    });

    const WELL_KNOWN_USERS = new Set([
      "system", "local service", "network service", "anonymous logon",
      "default", "default user", "public", "all users", "administrator"
    ]);

    const WELL_KNOWN_ACCOUNTS = new Set([
      "nt authority\\system", "nt authority\\local service",
      "nt authority\\network service", "nt authority\\anonymous logon",
      "builtin\\administrators"
    ]);

    function normalizeValue(category, value) {
      const text = String(value);
      if (["identities", "emails", "phones", "addresses", "clientDomains", "internalIPs", "publicIPs", "hostnames"].includes(category)) {
        return text.toLowerCase();
      }
      return text;
    }

    function entryKey(category, value) {
      return String(category) + "\u0000" + normalizeValue(category, value);
    }

    function createState(imported) {
      const state = {
        entries: [],
        byToken: new Map(),
        byValue: new Map(),
        counters: Object.create(null)
      };
      if (imported && Array.isArray(imported.mappings)) {
        if (imported.mappings.length > MAX_IMPORTED_MAPPINGS) throw new Error("Restore key contains too many mappings.");
        for (const item of imported.mappings) {
          if (!item || typeof item.token !== "string" || typeof item.original !== "string" || typeof item.category !== "string") continue;
          if (!item.token || item.token.length > 200 || /[\r\n\0]/.test(item.token) || item.original.length > 200000 || !item.category || item.category.length > 64 || state.byToken.has(item.token)) continue;
          const label = typeof item.label === "string" && item.label.length <= 100 ? item.label : "";
          const entry = { token: item.token, original: item.original, category: item.category, label, reviewed: item.reviewed === true };
          state.entries.push(entry);
          state.byToken.set(entry.token, entry);
          state.byValue.set(entry.category + "\u0000" + normalizeValue(entry.category, entry.original), entry.token);
          const suffix = entry.token.match(/_(\d+)>?$/);
          if (suffix) state.counters[entry.category] = Math.max(state.counters[entry.category] || 0, Number(suffix[1]));
        }
      }
      return state;
    }

    function nextNumber(state, category) {
      state.counters[category] = (state.counters[category] || 0) + 1;
      return state.counters[category];
    }

    function uniqueToken(state, proposed) {
      if (!state.byToken.has(proposed)) return proposed;
      let i = 2;
      while (state.byToken.has(proposed + "_" + i)) i += 1;
      return proposed + "_" + i;
    }

    function maskValue(state, category, original, options = {}) {
      const value = String(original);
      const key = entryKey(category, value);
      const existing = state.byValue.get(key);
      if (existing) {
        const entry = state.byToken.get(existing);
        if (entry && options.reviewed === true) entry.reviewed = true;
        return existing;
      }

      const number = nextNumber(state, category);
      let token;
      if (typeof options.template === "string" && options.template) {
        token = options.template.includes("{n}")
          ? options.template.split("{n}").join(String(number))
          : options.template + "_" + number;
      } else {
        token = "<" + (options.prefix || CATEGORY_PREFIX[category] || "MASK") + "_" + number + ">";
      }
      token = uniqueToken(state, token);
      const entry = { token, original: value, category, label: options.label || "", reviewed: options.reviewed === true };
      state.entries.push(entry);
      state.byToken.set(token, entry);
      state.byValue.set(key, token);
      return token;
    }

    function parseIPv4(input) {
      const text = String(input).trim();
      const parts = text.split(".");
      if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p))) return null;
      const octets = parts.map(Number);
      if (octets.some(n => n < 0 || n > 255)) return null;
      const value = octets.reduce((acc, n) => acc * 256 + n, 0);
      return { text, octets, value };
    }

    function classifyIPv4(input) {
      const parsed = parseIPv4(input);
      if (!parsed) return null;
      const [a, b] = parsed.octets;
      const internal = a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a === 127 ||
        (a === 169 && b === 254) ||
        (a === 100 && b >= 64 && b <= 127);
      return { family: 4, kind: internal ? "internal" : "public", value: BigInt(parsed.value), normalized: parsed.octets.join(".") };
    }

    function isLikelyIPv4Version(source, start) {
      const context = String(source).slice(Math.max(0, start - 32), start);
      return /(?:java|version|ver|build|release|runtime|python|node(?:\.js)?)[\s/:=_-]*$/i.test(context);
    }

    function parseIPv6(input) {
      let text = String(input).trim();
      if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
      const zoneAt = text.indexOf("%");
      if (zoneAt !== -1) text = text.slice(0, zoneAt);
      if (!text.includes(":")) return null;

      const v4Match = text.match(/(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/);
      const hadEmbeddedV4 = Boolean(v4Match);
      if (v4Match) {
        const v4 = parseIPv4(v4Match[1]);
        if (!v4) return null;
        const hi = ((v4.octets[0] << 8) | v4.octets[1]).toString(16);
        const lo = ((v4.octets[2] << 8) | v4.octets[3]).toString(16);
        text = text.slice(0, text.length - v4Match[1].length) + hi + ":" + lo;
      }

      if ((text.match(/::/g) || []).length > 1) return null;
      let groups;
      if (text.includes("::")) {
        const [left, right] = text.split("::");
        const leftParts = left ? left.split(":") : [];
        const rightParts = right ? right.split(":") : [];
        const missing = 8 - leftParts.length - rightParts.length;
        if (missing < 1) return null;
        groups = leftParts.concat(Array(missing).fill("0"), rightParts);
      } else {
        groups = text.split(":");
        if (groups.length !== 8) return null;
      }
      if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
      const nums = groups.map(g => parseInt(g, 16));
      let value = 0n;
      for (const n of nums) value = (value << 16n) | BigInt(n);
      return { text, groups: nums, value, normalized: nums.map(n => n.toString(16)).join(":"), hadEmbeddedV4 };
    }

    function classifyIPv6(input) {
      const parsed = parseIPv6(input);
      if (!parsed) return null;
      const ula = (parsed.value >> 121n) === 0x7en; // fc00::/7
      const linkLocal = (parsed.value >> 118n) === 0x3fan; // fe80::/10
      const loopback = parsed.value === 1n;
      const mappedV4 = parsed.hadEmbeddedV4 && parsed.groups.slice(0, 5).every(n => n === 0) && (parsed.groups[5] === 0 || parsed.groups[5] === 0xffff);
      if (mappedV4) {
        const v4Number = parsed.groups[6] * 65536 + parsed.groups[7];
        const v4 = [Math.floor(v4Number / 16777216) % 256, Math.floor(v4Number / 65536) % 256, Math.floor(v4Number / 256) % 256, v4Number % 256].join(".");
        const v4Class = classifyIPv4(v4);
        return { family: 6, kind: v4Class && v4Class.kind === "internal" ? "internal" : "public", value: parsed.value, normalized: parsed.normalized };
      }
      return { family: 6, kind: ula || linkLocal || loopback ? "internal" : "public", value: parsed.value, normalized: parsed.normalized };
    }

    function parseList(text) {
      return String(text || "").split(/\r?\n|,/).map(v => v.trim()).filter(v => v && !v.startsWith("#"));
    }

    function ipv4InCidr(ip, cidr) {
      const pieces = cidr.split("/");
      if (pieces.length !== 2) return false;
      const base = parseIPv4(pieces[0]);
      const target = parseIPv4(ip);
      const bits = Number(pieces[1]);
      if (!base || !target || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
      const block = 2 ** (32 - bits);
      return Math.floor(base.value / block) === Math.floor(target.value / block);
    }

    function ipv6InCidr(ip, cidr) {
      const slash = cidr.lastIndexOf("/");
      if (slash === -1) return false;
      const base = parseIPv6(cidr.slice(0, slash));
      const target = parseIPv6(ip);
      const bits = Number(cidr.slice(slash + 1));
      if (!base || !target || !Number.isInteger(bits) || bits < 0 || bits > 128) return false;
      if (bits === 0) return true;
      const shift = BigInt(128 - bits);
      return (base.value >> shift) === (target.value >> shift);
    }

    function isAllowlisted(value, allowlist) {
      const candidate = String(value).replace(/^\[|\]$/g, "").toLowerCase();
      for (const raw of allowlist || []) {
        const rule = String(raw).trim().toLowerCase();
        if (!rule) continue;
        if (rule === candidate) return true;
        if (rule.startsWith("*.") && (candidate === rule.slice(2) || candidate.endsWith(rule.slice(1)))) return true;
        if (rule.includes("/")) {
          if (candidate.includes(":") ? ipv6InCidr(candidate, rule) : ipv4InCidr(candidate, rule)) return true;
        }
      }
      return false;
    }

    function escapeRegex(value) {
      return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }

    function safeSecret(value) {
      const v = String(value).trim().replace(/^['"]|['"]$/g, "");
      if (v.length < 4) return true;
      if (/^(?:true|false|null|none|undefined|redacted|masked|example|sample|changeme|password|secret|token|\*+)$/i.test(v)) return true;
      if (/^<[^>]+>$/.test(v) || /^\$\{[^}]+}$/.test(v) || /^%[^%]+%$/.test(v)) return true;
      if (/^[0-9a-f]{32,128}$/i.test(v)) return true; // hashes are evidence, not assumed secrets
      if (/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(v)) return true; // GUIDs
      return false;
    }

    function validateConfig(config) {
      if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("Configuration must be a JSON object.");
      const cleanList = (name, value, maxLength) => {
        if (!Array.isArray(value)) throw new Error(name + " must be a list.");
        if (value.length > MAX_CONFIG_LIST_ITEMS) throw new Error(name + " contains too many entries.");
        const items = value.map(v => String(v).trim()).filter(Boolean);
        if (items.some(item => item.length > maxLength || /[\r\n\0]/.test(item))) throw new Error(name + " contains an invalid or oversized entry.");
        return Array.from(new Set(items));
      };
      const clean = {
        version: 1,
        clientDomains: Array.from(new Set(cleanList("Client domains", config.clientDomains || [], 253).map(v => v.toLowerCase()))),
        netbiosDomains: Array.from(new Set(cleanList("NetBIOS domains", config.netbiosDomains || [], 63).map(v => v.toLowerCase()))),
        iocAllowlist: cleanList("IOC allowlist", config.iocAllowlist || [], 512),
        customRules: []
      };
      if (!Array.isArray(config.customRules)) throw new Error("Custom rules must be a JSON array.");
      if (config.customRules.length > MAX_CUSTOM_RULES) throw new Error("Custom rules are limited to " + MAX_CUSTOM_RULES + " entries.");
      for (const [index, rule] of config.customRules.entries()) {
        if (!rule || typeof rule.name !== "string" || typeof rule.regex !== "string" || typeof rule.replacement !== "string") {
          throw new Error("Custom rule " + (index + 1) + " must contain string name, regex, and replacement values.");
        }
        if (rule.name.length > 80) throw new Error("Custom rule " + (index + 1) + " has a name longer than 80 characters.");
        if (!rule.regex || rule.regex.length > MAX_CUSTOM_REGEX_LENGTH) throw new Error("Custom rule " + (index + 1) + " must have a regex between 1 and " + MAX_CUSTOM_REGEX_LENGTH + " characters.");
        if (!rule.replacement || rule.replacement.length > 200 || /[\r\n\0]/.test(rule.replacement)) throw new Error("Custom rule " + (index + 1) + " has an invalid replacement token.");
        const flags = typeof rule.flags === "string" ? rule.flags : "gi";
        if (!/^[dgimsuvy]*$/.test(flags) || flags.includes("y")) throw new Error("Custom rule " + rule.name + " has unsupported flags.");
        const finalFlags = flags.includes("g") ? flags : flags + "g";
        try { new RegExp(rule.regex, finalFlags); } catch (error) { throw new Error("Invalid regex in custom rule " + rule.name + ": " + error.message); }
        clean.customRules.push({ name: rule.name.trim() || "custom", regex: rule.regex, replacement: rule.replacement, flags: finalFlags });
      }
      return clean;
    }

    function isWindowsPathPosition(text, start) {
      const source = String(text);
      const lineStart = source.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
      const prefix = source.slice(lineStart, start);
      const driveMatches = Array.from(prefix.matchAll(/[a-z]:\\/gi));
      const uncMatch = prefix.match(/(?:^|[\s"'(])\\\\[^\s\\]+\\/);
      if (!driveMatches.length && !uncMatch) return false;

      const pathStart = driveMatches.length ? driveMatches[driveMatches.length - 1].index : uncMatch.index;
      const beforePath = prefix.slice(0, pathStart);
      const pathPrefix = prefix.slice(pathStart);
      const openingQuote = beforePath.lastIndexOf('"');
      if (openingQuote !== -1 && prefix.indexOf('"', pathStart) !== -1) return false;
      if (/[|><;&]\s*$/.test(prefix)) return false;
      if (/\.(?:exe|com|bat|cmd|ps1)\b\s+.+$/i.test(pathPrefix)) return false;
      if (/(?:^|\s)(?:\/user(?:name)?|--user(?:name)?|user(?:name)?|account(?:name)?)\s*[:=]?\s*$/i.test(prefix)) return false;
      return true;
    }

    function isBuiltInAccountFragment(text, start, domain) {
      const source = String(text);
      const lineStart = source.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
      const before = source.slice(lineStart, start).toLowerCase();
      const name = String(domain).toLowerCase();
      if (name === "builtin") return true;
      if ((name === "authority" || name === "service") && /\bnt\s+$/.test(before)) return true;
      if (name === "manager" && /\bwindow\s+$/.test(before)) return true;
      if (name === "host" && /\bfont\s+driver\s+$/.test(before)) return true;
      if (name === "apppool" && /\biis\s+$/.test(before)) return true;
      return false;
    }

    function isRegistryPathPosition(text, start, domain) {
      const roots = /^(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)$/i;
      if (roots.test(String(domain))) return true;
      const source = String(text);
      const lineStart = source.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
      const prefix = source.slice(lineStart, start);
      const rootPattern = /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC):?\\/gi;
      const matches = Array.from(prefix.matchAll(rootPattern));
      if (!matches.length) return false;
      const rootStart = matches[matches.length - 1].index;
      const beforeRoot = prefix.slice(0, rootStart);
      const openingQuote = beforeRoot.lastIndexOf('"');
      if (openingQuote !== -1 && prefix.indexOf('"', rootStart) !== -1) return false;
      if (/[|><;&]\s*$/.test(prefix)) return false;
      return true;
    }

    function discoverIdentities(text, config, state, enabled = true) {
      if (!enabled) return state;
      // The leading delimiter deliberately excludes backslashes and slashes so
      // path segments such as Windows\System32 can never be read as accounts.
      const accountPattern = /(^|[\s>(\[\{,:;])([a-z][a-z0-9_.-]{0,63})\\([a-z0-9][a-z0-9._$-]{0,127})\b/gim;
      let match;
      while ((match = accountPattern.exec(text))) {
        const start = match.index + match[1].length;
        if (isWindowsPathPosition(text, start) || isRegistryPathPosition(text, start, match[2]) || isBuiltInAccountFragment(text, start, match[2])) continue;
        const account = (match[2] + "\\" + match[3]).toLowerCase();
        if (WELL_KNOWN_ACCOUNTS.has(account)) continue;
        if (!WELL_KNOWN_USERS.has(match[3].toLowerCase())) maskValue(state, "identities", match[3], { prefix: "USER" });
      }
      const emailPattern = /\b([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-z0-9.-]+\.[a-z]{2,63})\b/gi;
      while ((match = emailPattern.exec(text))) {
        if (!WELL_KNOWN_USERS.has(match[1].toLowerCase())) maskValue(state, "identities", match[1], { prefix: "USER" });
      }
      const windowsProfilePattern = /\b[a-z]:\\Users\\([^\\/\r\n]+)/gi;
      while ((match = windowsProfilePattern.exec(text))) {
        if (!WELL_KNOWN_USERS.has(match[1].toLowerCase())) maskValue(state, "identities", match[1], { prefix: "USER" });
      }
      const unixProfilePattern = /(?:^|[\s"'])(?:\/home\/|\/Users\/)([^\/\s"']+)/gim;
      while ((match = unixProfilePattern.exec(text))) {
        if (!WELL_KNOWN_USERS.has(match[1].toLowerCase())) maskValue(state, "identities", match[1], { prefix: "USER" });
      }
      return state;
    }

    function applyUserProfilePaths(text, state) {
      let output = text;
      output = output.replace(/(\b[a-z]:\\Users\\)([^\\/\r\n]+)/gi, (all, prefix, user) => {
        if (WELL_KNOWN_USERS.has(user.toLowerCase())) return all;
        return prefix + maskValue(state, "identities", user, { prefix: "USER" });
      });
      output = output.replace(/(^|[\s"'])((?:\/home\/|\/Users\/))([^\/\s"']+)/gim, (all, before, prefix, user) => {
        if (WELL_KNOWN_USERS.has(user.toLowerCase())) return all;
        return before + prefix + maskValue(state, "identities", user, { prefix: "USER" });
      });
      return output;
    }

    function applySecrets(text, state) {
      let output = text;
      const directPatterns = [
        /\bAKIA[0-9A-Z]{16}\b/g,
        /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b/g,
        /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
        /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g,
        /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
      ];
      for (const re of directPatterns) {
        output = output.replace(re, value => safeSecret(value) ? value : maskValue(state, "secrets", value, { prefix: "SECRET" }));
      }
      output = output.replace(/\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})/gi, (all, prefix, value) => {
        return safeSecret(value) ? all : prefix + maskValue(state, "secrets", value, { prefix: "SECRET" });
      });
      output = output.replace(/\b(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)(\s*[:=]\s*)(["']?)([^\s"',;&]{4,})(["']?)/gi,
        (all, key, separator, quoteA, value, quoteB) => {
          if ((quoteA || quoteB) && quoteA !== quoteB) return all;
          return safeSecret(value) ? all : key + separator + quoteA + maskValue(state, "secrets", value, { prefix: "SECRET" }) + quoteB;
        });
      output = output.replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
        value => maskValue(state, "secrets", value, { prefix: "PRIVATE_KEY" }));
      return output;
    }

    function applyPersonalData(text, state, enabled = true) {
      if (!enabled) return text;
      let output = String(text);

      // Mask the entire email address, including its domain. Both normal dots
      // and common defanged separators such as [.] and [dot] are supported.
      const emailAddress = /\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:(?:\.|\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\})[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi;
      output = output.replace(emailAddress, value => maskValue(state, "emails", value, { prefix: "EMAIL", label: "Email" }));

      // Require an international prefix and 7–15 digits to avoid confusing
      // timestamps, ports, PIDs, and ordinary log numbers with phone numbers.
      const internationalPhone = /(^|[^A-Za-z0-9_])(\+(?:\d[\s().-]*){6,14}\d)(?=$|[^A-Za-z0-9_])/g;
      output = output.replace(internationalPhone, (all, before, value) => {
        const digits = value.replace(/\D/g, "");
        return digits.length >= 7 && digits.length <= 15
          ? before + maskValue(state, "phones", value, { prefix: "PHONE", label: "Phone number" })
          : all;
      });

      // High-confidence single-line postal address: street + house number,
      // postal code + city, country. Unicode letters support non-English text.
      const postalAddress = /(^|\r?\n)([ \t]*(?:[-*•]\s*)?)([\p{L}][\p{L}.'’\-]*(?:[ \t]+[\p{L}][\p{L}.'’\-]*){0,5}[ \t]+\d{1,5}[A-Za-z]?(?:\/\d{1,5})?,[ \t]*\d{4,6}[ \t]+[\p{L}][\p{L}.'’\-]*(?:[ \t]+[\p{L}][\p{L}.'’\-]*){0,4},[ \t]*[\p{L}][\p{L}.'’\-]*(?:[ \t]+[\p{L}][\p{L}.'’\-]*){0,3})(?=[ \t]*(?:`)?(?:\r?$))/gmu;
      output = output.replace(postalAddress, (all, lineStart, prefix, value) => lineStart + prefix + maskValue(state, "addresses", value, { prefix: "ADDRESS", label: "Postal address" }));
      return output;
    }

    function applyDomains(text, config, state, options) {
      let output = text;
      const domains = config.clientDomains.slice().sort((a, b) => b.length - a.length);
      if (options.clientDomains) {
        for (const domain of domains) {
          const re = new RegExp("(^|[^a-z0-9.-])((?:[a-z0-9-]+\\.)*" + escapeRegex(domain) + ")(?=$|[^a-z0-9.-])", "gi");
          output = output.replace(re, (all, before, value) => {
            if (isAllowlisted(value, config.iocAllowlist)) return all;
            return before + maskValue(state, "clientDomains", value, { prefix: "DOMAIN" });
          });
        }
      }
      if (options.identities || options.clientDomains) {
        const accountPattern = /(^|[\s>(\[\{,:;])([a-z][a-z0-9_.-]{0,63})\\([a-z0-9][a-z0-9._$-]{0,127})\b/gim;
        output = output.replace(accountPattern, (all, before, domain, user, offset, source) => {
          const start = offset + before.length;
          if (isWindowsPathPosition(source, start) || isRegistryPathPosition(source, start, domain) || isBuiltInAccountFragment(source, start, domain)) return all;
          if (WELL_KNOWN_ACCOUNTS.has((domain + "\\" + user).toLowerCase())) return all;
          const domainOut = options.clientDomains
            ? maskValue(state, "clientDomains", domain, { prefix: "NETBIOS" }) : domain;
          const userOut = options.identities && !WELL_KNOWN_USERS.has(user.toLowerCase())
            ? maskValue(state, "identities", user, { prefix: "USER" }) : user;
          return before + domainOut + "\\" + userOut;
        });
        if (options.clientDomains) {
          for (const netbios of config.netbiosDomains.slice().sort((a, b) => b.length - a.length)) {
            const re = new RegExp("(^|[^a-z0-9_.-])(" + escapeRegex(netbios) + ")(?=$|[^a-z0-9_.-])", "gi");
            output = output.replace(re, (all, before, value) => before + maskValue(state, "clientDomains", value, { prefix: "NETBIOS" }));
          }
        }
      }
      return output;
    }

    function applyKnownStandaloneIdentities(text, state) {
      let output = String(text);
      const dottedUsers = state.entries.filter(entry => entry.category === "identities" && /^[a-z][a-z'-]{1,31}(?:\.[a-z][a-z'-]{1,31}){1,3}$/i.test(entry.original));
      for (const entry of dottedUsers) {
        const re = new RegExp("(^|[^a-z0-9._@\\\\/'-])(" + escapeRegex(entry.original) + ")(?=$|[^a-z0-9._@\\\\/'-])", "gi");
        output = output.replace(re, (all, before) => before + entry.token);
      }
      return output;
    }

    function applyIdentityFormats(text, config, state, options) {
      if (!options.identities) return text;
      let output = text;
      output = output.replace(/\bS-1-(?:\d+-){2,14}\d+\b/gi, value => maskValue(state, "identities", value, { prefix: "SID" }));
      output = output.replace(/\b([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-z0-9.-]+\.[a-z]{2,63})\b/gi, (all, user, domain) => {
        const userOut = WELL_KNOWN_USERS.has(user.toLowerCase()) ? user : maskValue(state, "identities", user, { prefix: "USER" });
        let domainOut = domain;
        const isClient = config.clientDomains.some(d => domain.toLowerCase() === d || domain.toLowerCase().endsWith("." + d));
        if (options.clientDomains && isClient && !isAllowlisted(domain, config.iocAllowlist)) {
          domainOut = maskValue(state, "clientDomains", domain, { prefix: "DOMAIN" });
        }
        return userOut + "@" + domainOut;
      });
      output = applyUserProfilePaths(output, state);
      return applyKnownStandaloneIdentities(output, state);
    }

    function applyIPs(text, config, state, options) {
      let output = text;
      const v4Pattern = /(^|[^a-z0-9.])((?:\d{1,3}\.){3}\d{1,3})(?=$|[^a-z0-9.])/gi;
      output = output.replace(v4Pattern, (all, before, ip, offset, source) => {
        const classification = classifyIPv4(ip);
        if (!classification || isLikelyIPv4Version(source, offset + before.length) || isAllowlisted(ip, config.iocAllowlist)) return all;
        if (classification.kind === "internal" && options.internalIPs) return before + maskValue(state, "internalIPs", ip, { prefix: "IP_INTERNAL" });
        if (classification.kind === "public" && options.publicIPs) return before + maskValue(state, "publicIPs", ip, { prefix: "IP_PUBLIC" });
        return all;
      });

      const v6Pattern = /(^|[^a-z0-9:])((?:\[[0-9a-f:.%_-]+\])|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f:.]{0,15}(?:%[a-z0-9_.-]+)?)(?=$|[^a-z0-9:])/gi;
      output = output.replace(v6Pattern, (all, before, ip) => {
        const classification = classifyIPv6(ip);
        if (!classification || isAllowlisted(ip, config.iocAllowlist)) return all;
        if (classification.kind === "internal" && options.internalIPs) return before + maskValue(state, "internalIPs", ip, { prefix: "IP_INTERNAL" });
        if (classification.kind === "public" && options.publicIPs) return before + maskValue(state, "publicIPs", ip, { prefix: "IP_PUBLIC" });
        return all;
      });
      return output;
    }

    function applyCustomRules(text, config, state) {
      let output = text;
      for (const rule of config.customRules) {
        const re = new RegExp(rule.regex, rule.flags);
        output = output.replace(re, (...args) => {
          const full = args[0];
          if (!full || state.byToken.has(full)) return full;
          return maskValue(state, "custom", full, { template: rule.replacement, label: rule.name });
        });
      }
      return output;
    }

    function countLiteral(text, value) {
      const source = String(text).toLowerCase();
      const needle = String(value).toLowerCase();
      if (!needle) return 0;
      let count = 0;
      let at = 0;
      while ((at = source.indexOf(needle, at)) !== -1) {
        count += 1;
        at += needle.length;
      }
      return count;
    }

    function detectSuggestions(text, rawConfig) {
      const source = String(text);
      const config = validateConfig(rawConfig);
      const found = new Map();
      const add = (type, value, category, prefix, label) => {
        const clean = String(value);
        if (!clean || clean.startsWith("<") || isAllowlisted(clean, config.iocAllowlist)) return;
        const key = type + "\u0000" + clean.toLowerCase();
        if (!found.has(key)) found.set(key, { key, type, value: clean, category, prefix, label, occurrences: countLiteral(source, clean) });
      };

      let match;
      const v4Pattern = /(^|[^a-z0-9.])((?:\d{1,3}\.){3}\d{1,3})(?=$|[^a-z0-9.])/gi;
      while ((match = v4Pattern.exec(source))) {
        const classification = classifyIPv4(match[2]);
        const start = match.index + match[1].length;
        if (classification && classification.kind === "public" && !isLikelyIPv4Version(source, start)) add("Public IP", match[2], "publicIPs", "IP_PUBLIC", "Public IP");
      }

      const v6Pattern = /(^|[^a-z0-9:])((?:\[[0-9a-f:.%_-]+\])|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f:.]{0,15}(?:%[a-z0-9_.-]+)?)(?=$|[^a-z0-9:])/gi;
      while ((match = v6Pattern.exec(source))) {
        const classification = classifyIPv6(match[2]);
        if (classification && classification.kind === "public") add("Public IP", match[2], "publicIPs", "IP_PUBLIC", "Public IP");
      }

      const fileExtensions = new Set(["exe", "dll", "sys", "scr", "msi", "msp", "txt", "log", "json", "csv", "xml", "md", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z", "gz", "tar", "ps1", "psm1", "bat", "cmd", "vbs", "js", "jse", "py", "sh", "conf", "config", "ini", "dat", "tmp", "bak"]);
      const knownDomainSuffixes = new Set(["com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "io", "co", "ai", "app", "dev", "cloud", "tech", "me", "eu", "cz", "sk", "de", "at", "pl", "uk", "fr", "it", "es", "nl", "be", "ch", "se", "no", "fi", "dk", "ie", "pt", "gr", "ro", "hu", "si", "hr", "bg", "lt", "lv", "ee", "lu", "us", "ca", "mx", "br", "ar", "au", "nz", "jp", "cn", "in", "sg", "ae", "sa", "iq", "tr", "ru", "ua", "za", "local", "internal", "corp", "example", "test", "invalid", "localhost"]);
      const dottedUsernameCandidates = new Set();
      const dottedUsernamePattern = /\b[a-z][a-z'-]{1,31}(?:\.[a-z][a-z'-]{1,31}){1,3}\b/gi;
      while ((match = dottedUsernamePattern.exec(source))) {
        const value = match[0];
        const suffix = value.slice(value.lastIndexOf(".") + 1).toLowerCase();
        const before = source[match.index - 1] || "";
        const after = source[match.index + value.length] || "";
        if (/[a-z0-9._@\\\/-]/i.test(before) || /[a-z0-9._@\\\/-]/i.test(after)) continue;
        if (fileExtensions.has(suffix) || knownDomainSuffixes.has(suffix)) continue;
        dottedUsernameCandidates.add(value.toLowerCase());
        add("Username", value, "identities", "USER", "Suggested dotted username");
      }
      const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,63}\b/gi;
      while ((match = domainPattern.exec(source))) {
        const value = match[0];
        const suffix = value.slice(value.lastIndexOf(".") + 1).toLowerCase();
        const isConfigured = config.clientDomains.some(domain => value.toLowerCase() === domain || value.toLowerCase().endsWith("." + domain));
        if (!fileExtensions.has(suffix) && !isConfigured && !dottedUsernameCandidates.has(value.toLowerCase())) add("Unknown domain", value, "clientDomains", "DOMAIN", "Suggested domain");
      }

      const hostnamePattern = /\b(?=[a-z0-9-]{4,63}\b)(?=[a-z0-9-]*\d)(?:srv|server|ws|wkstn|workstation|desktop|laptop|host|vm|dc|sql|db|web|app|prod|dev|test|uat|pc)[a-z0-9-]*\b/gi;
      while ((match = hostnamePattern.exec(source))) {
        const value = match[0];
        const before = source[match.index - 1] || "";
        const after = source[match.index + value.length] || "";
        if (before === "." || after === "." || /^[0-9a-f]{16,}$/i.test(value)) continue;
        add("Hostname", value, "hostnames", "HOST", "Hostname");
      }

      const usernamePattern = /\b(?:user(?:name)?|account(?:name)?|targetuser(?:name)?|initiatingprocessaccountname)\s*[:=]\s*([a-z][a-z0-9._$-]{2,63})\b/gi;
      while ((match = usernamePattern.exec(source))) {
        if (!WELL_KNOWN_USERS.has(match[1].toLowerCase())) add("Username", match[1], "identities", "USER", "Suggested username");
      }

      return Array.from(found.values()).sort((a, b) => a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
    }

    function applySuggestions(text, suggestions, state) {
      let output = String(text);
      for (const suggestion of suggestions || []) {
        if (!suggestion || !suggestion.value) continue;
        const escaped = escapeRegex(suggestion.value);
        let re;
        if (suggestion.type === "Public IP") re = new RegExp("(^|[^a-z0-9.])(" + escaped + ")(?=$|[^a-z0-9.])", "gi");
        else if (suggestion.type === "Unknown domain") re = new RegExp("(^|[^a-z0-9.-])(" + escaped + ")(?=$|[^a-z0-9.-])", "gi");
        else re = new RegExp("(^|[^a-z0-9_$.-])(" + escaped + ")(?=$|[^a-z0-9_$.-])", "gi");
        output = output.replace(re, (all, before, value) => before + maskValue(state, suggestion.category, value, { prefix: suggestion.prefix, label: suggestion.label, reviewed: true }));
      }
      return output;
    }

    function applyManualValues(text, values, state) {
      let output = String(text);
      for (const raw of values || []) {
        const value = String(raw).trim();
        if (!value) continue;
        const startsWithWord = /^[a-z0-9_]/i.test(value);
        const endsWithWord = /[a-z0-9_]$/i.test(value);
        const prefix = startsWithWord ? "(^|[^A-Za-z0-9_])" : "()";
        const suffix = endsWithWord ? "(?=$|[^A-Za-z0-9_])" : "";
        const re = new RegExp(prefix + "(" + escapeRegex(value) + ")" + suffix, "g");
        output = output.replace(re, (all, before, matched) => before + maskValue(state, "manual", matched, { prefix: "MASK", label: "Manual selection", reviewed: true }));
      }
      return output;
    }

    function sanitizeChunk(text, rawConfig, options, state) {
      const config = validateConfig(rawConfig);
      let output = String(text);
      if (options.secrets) output = applySecrets(output, state);
      output = applyPersonalData(output, state, options.identities);
      output = applyDomains(output, config, state, options);
      output = applyIdentityFormats(output, config, state, options);
      output = applyIPs(output, config, state, options);
      output = applyCustomRules(output, config, state);
      return output;
    }

    function restore(text, state) {
      let output = String(text);
      const entries = state.entries.slice().sort((a, b) => b.token.length - a.token.length);
      for (const entry of entries) output = output.split(entry.token).join(entry.original);
      return output;
    }

    function unmaskValues(text, state, keys) {
      const selected = new Set(keys || []);
      if (!selected.size) return String(text);
      let output = String(text);
      const removed = [];
      for (const entry of state.entries.slice()) {
        if (!selected.has(entryKey(entry.category, entry.original))) continue;
        output = output.split(entry.token).join(entry.original);
        removed.push(entry);
      }
      if (removed.length) {
        const removedTokens = new Set(removed.map(entry => entry.token));
        state.entries = state.entries.filter(entry => !removedTokens.has(entry.token));
        for (const entry of removed) {
          state.byToken.delete(entry.token);
          state.byValue.delete(entryKey(entry.category, entry.original));
        }
      }
      return output;
    }

    function mappingJSON(state) {
      return {
        format: "log-sani-mapping",
        version: 1,
        createdAt: new Date().toISOString(),
        mappings: state.entries.map(({ token, original, category, label, reviewed }) => ({ token, original, category, ...(label ? { label } : {}), ...(reviewed ? { reviewed: true } : {}) }))
      };
    }

    function countTokens(text, state) {
      const counts = { internalIPs: 0, identities: 0, emails: 0, phones: 0, addresses: 0, clientDomains: 0, secrets: 0, publicIPs: 0, custom: 0 };
      const source = String(text);
      for (const entry of state.entries) {
        let at = 0;
        while ((at = source.indexOf(entry.token, at)) !== -1) {
          if (Object.hasOwn(counts, entry.category)) counts[entry.category] += 1;
          at += entry.token.length || 1;
        }
      }
      return counts;
    }

    function runTests() {
      const results = [];
      const check = (name, condition) => results.push({ name, pass: Boolean(condition) });
      check("RFC1918 IPv4", classifyIPv4("10.202.34.146")?.kind === "internal" && classifyIPv4("172.31.9.2")?.kind === "internal");
      check("Loopback/link-local/CGNAT IPv4", ["127.0.0.1", "169.254.4.2", "100.127.255.1"].every(v => classifyIPv4(v)?.kind === "internal"));
      check("Public IPv4", classifyIPv4("8.8.8.8")?.kind === "public");
      check("IPv4 validation", classifyIPv4("999.1.1.1") === null);
      check("ULA/link-local/loopback IPv6", ["fd12:3456::1", "fe80::abcd", "::1"].every(v => classifyIPv6(v)?.kind === "internal"));
      check("Public IPv6", classifyIPv6("2001:4860:4860::8888")?.kind === "public");

      const config = validateConfig({
        clientDomains: ["client.example"],
        netbiosDomains: ["EUR"],
        iocAllowlist: ["8.8.8.8"],
        customRules: [{ name: "host", regex: "\\bHOST-[0-9]+\\b", replacement: "<HOST_{n}>" }]
      });
      const options = { internalIPs: true, identities: true, clientDomains: true, secrets: true, publicIPs: true };
      const state = createState();
      const fixture = "**Sep 18, 2026 11:50:56.361 AM**\nEUR\\analyst from 10.202.34.146:49922\nC:\\Users\\analyst\\file.txt\n8.8.8.8\npassword=RealSecret123!\nsha256=7f47f409540464266b1bd037c6ca19e487b8a726\nHOST-123";
      discoverIdentities(fixture, config, state, true);
      const masked = sanitizeChunk(fixture, config, options, state);
      check("Separate NetBIOS and username tokens", masked.includes("<NETBIOS_1>\\<USER_1>"));
      check("Consistent username in path", masked.includes("C:\\Users\\<USER_1>\\file.txt"));
      const systemPath = "c:\\windows\\system32\\lsass.exe\nC:\\Windows\\System32\ndllhost.exe";
      const pathState = createState();
      discoverIdentities(systemPath, config, pathState, true);
      const pathResult = sanitizeChunk(systemPath, config, options, pathState);
      check("Windows and System32 are never identities", pathResult === systemPath && pathState.entries.length === 0);
      const spacedPath = "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\nC:\\Program Files\\WindowsApps\\Local\\Platform";
      const spacedPathState = createState();
      discoverIdentities(spacedPath, config, spacedPathState, true);
      const spacedPathResult = sanitizeChunk(spacedPath, config, options, spacedPathState);
      check("Folders in spaced Windows paths are never identities", spacedPathResult === spacedPath && spacedPathState.entries.length === 0);
      const pathThenAccount = '"C:\\Program Files\\Tool\\tool.exe" /user EUR\\analyst';
      const pathThenAccountState = createState();
      discoverIdentities(pathThenAccount, config, pathThenAccountState, true);
      const pathThenAccountResult = sanitizeChunk(pathThenAccount, config, options, pathThenAccountState);
      check("Account after executable path is still masked", pathThenAccountResult.includes('"C:\\Program Files\\Tool\\tool.exe" /user <NETBIOS_1>\\<USER_1>'));
      const registryAndBuiltIns = "nt authority\\system\nnt authority\\local service\nnt service\\TrustedInstaller\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
      const registryState = createState();
      discoverIdentities(registryAndBuiltIns, config, registryState, true);
      const registryResult = sanitizeChunk(registryAndBuiltIns, config, options, registryState);
      check("Registry paths are never identities", registryResult.includes("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet") && registryResult.includes("Windows Defender\\Real-Time Protection"));
      check("Built-in Windows accounts are preserved", registryResult.includes("nt authority\\system") && registryResult.includes("nt authority\\local service") && registryResult.includes("nt service\\TrustedInstaller"));
      check("Registry and built-in values create no mappings", registryResult === registryAndBuiltIns && registryState.entries.length === 0);
      check("Port and timeline timestamp preserved", masked.includes(":49922") && masked.includes("11:50:56.361 AM"));
      check("Allowlisted IOC preserved", masked.includes("8.8.8.8"));
      check("Hash false-positive guard", masked.includes("7f47f409540464266b1bd037c6ca19e487b8a726"));
      check("Secret masked", !masked.includes("RealSecret123!") && masked.includes("<SECRET_1>"));
      check("Custom reversible rule", masked.includes("<HOST_1>") && restore(masked, state) === fixture);
      const autoAccountState = createState();
      const autoAccount = "EUR\\ggkuser";
      discoverIdentities(autoAccount, validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [] }), autoAccountState, true);
      const autoAccountMasked = sanitizeChunk(autoAccount, validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [] }), { internalIPs: true, identities: true, clientDomains: true, secrets: true, publicIPs: false }, autoAccountState);
      check("Account domain and username mask automatically", autoAccountMasked === "<NETBIOS_1>\\<USER_1>");
      const suggestionFixture = "8.8.4.4 evil.example dllhost.exe vmdev001";
      const suggestions = detectSuggestions(suggestionFixture, validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [] }));
      check("Public IP suggested for review", suggestions.some(item => item.type === "Public IP" && item.value === "8.8.4.4"));
      check("Unknown domain suggested but filename excluded", suggestions.some(item => item.type === "Unknown domain" && item.value === "evil.example") && !suggestions.some(item => item.value === "dllhost.exe"));
      check("Hostname suggested for review", suggestions.some(item => item.type === "Hostname" && item.value.toLowerCase() === "vmdev001"));
      const markdownIPs = detectSuggestions("[_4.234.34.123_, _4.234.34.86_] Java/17.0.20.1", validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [] }));
      check("Underscore-delimited public IPs suggested", markdownIPs.filter(item => item.type === "Public IP").length === 2 && markdownIPs.some(item => item.value === "4.234.34.123") && markdownIPs.some(item => item.value === "4.234.34.86"));
      check("Java version is not suggested as an IP", !markdownIPs.some(item => item.value === "17.0.20.1"));
      const reviewedState = createState();
      applySuggestions("4.234.34.123", markdownIPs.filter(item => item.value === "4.234.34.123"), reviewedState);
      check("Review-selected mapping is tagged", reviewedState.entries.length === 1 && reviewedState.entries[0].reviewed === true);
      const dottedIdentityState = createState();
      const dottedIdentityFixture = "jakub.kadasi@something.com signed in as jakub.kadasi";
      discoverIdentities(dottedIdentityFixture, config, dottedIdentityState, true);
      const dottedIdentityResult = sanitizeChunk(dottedIdentityFixture, config, options, dottedIdentityState);
      check("Full email is masked while standalone username remains masked", dottedIdentityResult === "<EMAIL_1> signed in as <USER_1>");
      const dottedSuggestions = detectSuggestions("jakub.kadasi Acrobat.exe something.com", validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [] }));
      check("Standalone dotted username is suggested", dottedSuggestions.some(item => item.type === "Username" && item.value === "jakub.kadasi"));
      check("Filename is excluded while domain remains a domain", !dottedSuggestions.some(item => item.value === "Acrobat.exe") && dottedSuggestions.some(item => item.type === "Unknown domain" && item.value === "something.com"));
      const manualState = createState();
      const manuallyMasked = applyManualValues("Adobe AdobeARM adobe", ["Adobe"], manualState);
      check("Manual exact-word masking is reversible", manuallyMasked === "<MASK_1> AdobeARM adobe" && manualState.entries[0].reviewed === true && restore(manuallyMasked, manualState) === "Adobe AdobeARM adobe");
      const personalState = createState();
      const personalFixture = "- `office@vpdima[.]rs`\n- +381 26 516 777\n- Milosa Velikog 150, 11320 Velika Plana, Serbia";
      const personalMasked = sanitizeChunk(personalFixture, config, options, personalState);
      check("Defanged email is masked", personalMasked.includes("`<EMAIL_1>`") && !personalMasked.includes("office@vpdima[.]rs"));
      const standardEmailState = createState();
      const standardEmailMasked = sanitizeChunk("wtf@gmail.com", config, options, standardEmailState);
      check("Standard email is masked completely", standardEmailMasked === "<EMAIL_1>" && !standardEmailMasked.includes("gmail.com"));
      check("International phone number is masked", personalMasked.includes("<PHONE_1>") && !personalMasked.includes("+381 26 516 777"));
      check("Postal address is masked", personalMasked.includes("<ADDRESS_1>") && !personalMasked.includes("Milosa Velikog 150"));
      const phoneKey = entryKey("phones", "+381 26 516 777");
      const partlyUnmasked = unmaskValues(personalMasked, personalState, [phoneKey]);
      check("One masked value can be unmasked", partlyUnmasked.includes("+381 26 516 777") && partlyUnmasked.includes("<EMAIL_1>") && partlyUnmasked.includes("<ADDRESS_1>") && !personalState.entries.some(entry => entry.category === "phones"));
      let oversizedRuleRejected = false;
      try {
        validateConfig({ clientDomains: [], netbiosDomains: [], iocAllowlist: [], customRules: [{ name: "too-long", regex: "a".repeat(MAX_CUSTOM_REGEX_LENGTH + 1), replacement: "<MASK_{n}>" }] });
      } catch (_) { oversizedRuleRejected = true; }
      check("Oversized custom regex is rejected", oversizedRuleRejected);
      let excessiveMappingsRejected = false;
      try { createState({ mappings: Array(MAX_IMPORTED_MAPPINGS + 1) }); }
      catch (_) { excessiveMappingsRejected = true; }
      check("Excessive restore mappings are rejected", excessiveMappingsRejected);
      return results;
    }

    return Object.freeze({
      createState, validateConfig, parseList, discoverIdentities, sanitizeChunk,
      restore, unmaskValues, entryKey, mappingJSON, countTokens, classifyIPv4, classifyIPv6,
      detectSuggestions, applySuggestions, applyManualValues, runTests
    });
  })();
