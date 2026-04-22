# vAnalyzer

> Security plugin for [Vencord](https://vencord.dev/) designed to analyze links, files, and user/server context within Discord.

> We know that Discord has a built-in analyzer, but this expands the possibilities 

![Status](https://img.shields.io/badge/Status-Active-green) ![Language](https://img.shields.io/badge/Language-TypeScript-blue)

---

# How To Install


### src/userplugins folder

> https://docs.vencord.dev/installing/#installing-your-custom-build
> 
> https://docs.vencord.dev/installing/custom-plugins/



---

## Quick Summary

vAnalyzer combines three layers:

1. **Manual analysis** from context menus
2. **Automatic analysis** when messages arrive (based on configuration)
3. **Visual enrichment** inside the message (results accessory)
4. **Custom modular scanning system** <img width="597" height="798" alt="image" src="https://github.com/user-attachments/assets/6b9a4e55-0297-40ed-b09a-d872133dde45" />


Features: whitelists/blacklists, local caching and custom modules to connect your own endpoints.

---

<img width="440" height="214" alt="image" src="https://github.com/user-attachments/assets/badf06e5-6ec2-47d5-9feb-c2d8b6d8ebca" />
<img width="457" height="213" alt="image" src="https://github.com/user-attachments/assets/f6137e24-8232-4c09-bd91-22b0c11401c9" />
Search unknown users
<img width="451" height="138" alt="image" src="https://github.com/user-attachments/assets/96c6c187-2007-4227-bd06-2470d2fd7159" />
<img width="574" height="666" alt="image" src="https://github.com/user-attachments/assets/0df6ef09-06da-412e-8b73-6355ec9d5c9a" />
<img width="620" height="269" alt="image" src="https://github.com/user-attachments/assets/a87b78f6-8fc4-4a12-af94-b756c090d78d" />
<img width="601" height="198" alt="image" src="https://github.com/user-attachments/assets/3f82ae52-6f7a-4836-8646-74cecf9e8491" />
<img width="629" height="358" alt="image" src="https://github.com/user-attachments/assets/caeb8d65-c035-4618-be56-e07794a71cc6" />
<img width="425" height="501" alt="image" src="https://github.com/user-attachments/assets/c9f60a3c-34c0-4368-9273-daa261b3d2cd" />
<img width="626" height="379" alt="image" src="https://github.com/user-attachments/assets/03fb8544-c000-4a73-8bfd-91473f430ad9" />

---

## Main Features

| Feature | Description | Where Used |
| --- | --- | --- |
| Manual context menus | On-demand scanning of URLs, attachments, invites, users | Messages, users, servers |
| Auto-analysis | Automatic analysis when messages arrive | MESSAGE_CREATE flow |
| Link click warning | Alert on flagged domains | Link click interception |
| Message age filter | Ignore old messages by days | Auto-analysis |
| DM-only mode | Limit auto-scan to direct messages | All analyzers |
| Skip friends | Avoid scanning friend messages | Auto-analysis |
| Ignore media files | Skip image/video/audio files | File auto-scan |
| Whitelist/blocklist | Exclude/flag domains | URL pipeline |
| FMHY auto-update | Fetch unsafe sites list | Blocklists |
| OSINT shortcuts | Search User / Search Server | User/server contexts |
| Modular Scan | Custom HTTP endpoints | URL/file analysis |
| Connected members | Public widget member list | Discord invite results |


### Base Analyzers

| Module | Type | Output | API Key Required |
| --- | --- | --- | --- |
| CertPL | Domain | Blocklist status | ✅ No |
| FishFish | Domain | Phishing check | ✅ No |
| WhereGoes | URL | Redirect chain | ✅ No |
| Sucuri | Domain | Reputation rating | ✅ No |
| CrtSh | Domain | Certificate history | ✅ No |
| DiscordInvite | Invite | Server info + widget | ✅ No |
| BotProfile | Bot | Account status | ✅ No |
| [VirusTotal](https://www.virustotal.com) | File | Scanner verdicts | ⚠️ Partial |
| [HybridAnalysis](https://hybrid-analysis.com/) | URL/File | Multi-scanner verdicts | ❌ Yes |
| [DangeCord](https://dangercord.com) | User | Reputation status | ❌ Yes |
| [CordCat](https://cord.cat/donate) | User | Reputation status | ✅ No |
| WaybackMachine | URL | Web archive snapshot | ✅ No |
| ModularScan | URL/File | Endpoint response | ⚠️ Depends |


### Discord Invite Details

When valid, includes:
- Server ID
- Member/online counts
- Verification level
- Features (Verified, Partnered, etc.)
- NSFW/scam keyword detection
- Public widget members (if enabled, up to 50 listed)

Note: Discord widget API has member listing limits. Plugin applies local cutoff of 50 members.

---

## Without API Key vs With API Key

**Without API Key (Available):**
- Discord invite analysis
- Domain blocklist checks (CERT.PL, FishFish, Sucuri, crt.sh)
- URL redirect tracing (WhereGoes)
- Bot profile analysis
- Whitelist/blocklist filters
- Search User / Search Server shortcuts, unknown user analyzer
- VirusTotal hash lookup (no upload)
- Modular Scan (if endpoint allows)

**With API Keys (Additional):**
- VirusTotal: File upload + report polling
- Hybrid Analysis: URL/file quick scan + result polling
- DangeCord: User reputation lookup

---

## Configuration

### API Keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| virusTotalApiKey | string | — | VirusTotal API key |
| dangecordApiKey | string | — | DangeCord API key |
| hybridAnalysisApiKey | string | — | Hybrid Analysis API key |

### Protection

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| warnOnLinkClick | bool | true | Alert on flagged link click |
| warnOnFileDownload | bool | true | Flag risky downloads |
| analyzeBotsProfile | bool | false | Auto-analyze bot profiles |
| enableOsintSearchShortcuts | bool | true | Search User / Server shortcuts |
| enableCordCat | bool | true | Show "Analyze with CordCat" |
| enableFindByUserId | bool | true | Show "Find By User Id" |

### Scope

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| skipFriends | bool | true | Skip friend messages |
| autoScanInvitesDirectMessageOnly | bool | false | Invites in DM only |
| autoScanUrlsDirectMessageOnly | bool | false | URLs in DM only |
| autoScanFilesDirectMessageOnly | bool | false | Files in DM only |
| messageAgeFilter | days | 3 | Messages older than X days (0=off) |

### URLs & Invites

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| autoScanInvites | bool | true | Auto-analyze invites |
| autoScanUrls | bool | false | Auto-scan URLs |
| autoScanUrlsCertPL | bool | true | CERT.PL check |
| autoScanUrlsFishFish | bool | true | FishFish check |
| autoScanUrlsWhereGoes | bool | true | Redirect tracing |
| autoScanUrlsSucuri | bool | true | Sucuri reputation |
| autoScanUrlsHybridAnalysis | bool | false | HA URL scan (needs API) |

### Files

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| autoScanFiles | bool | false | Auto-scan files |
| ignoreMediaFiles | bool | true | Skip image/video/audio |
| autoScanFilesVirusTotal | bool | true | VirusTotal scan |
| virusTotalLookupBeforeUpload | bool | true | Hash lookup first |
| autoScanFilesHybridAnalysis | bool | true | HA file scan |

### Filters

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| useBuiltinWhitelist | bool | true | Internal whitelist |
| enableBlocklists | bool | true | Blocklist checking |
| enableFmhyBlocklist | bool | true | FMHY Unsafe list |
| customWhitelist | str | — | Custom white domains |
| customBlocklist | str | — | Custom black domains |

### Advanced

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| modularScanSettings | UI | — | Custom HTTP module editor |

---

## Context Menus and Available Actions

### Message context

| Group | Actions |
| --- | --- |
| User | Scan author with DangeCord |
| Files | Scan file with VirusTotal / Hybrid Analysis |
| URL | Trace URL (WhereGoes), crt.sh, CERT.PL, FishFish, Sucuri, Hybrid Analysis |
| Invite | Analyze Discord invite |
| Modular | Run custom modules compatible with URL/file |

### User context

| Group | Actions |
| --- | --- |
| Search User | top.gg, DiscordHub |
| Reputation | Scan with DangeCord |

### Guild context / guild-header-popout

| Group | Actions |
| --- | --- |
| Search Server | Disboard, DiscordServers |

---

## Modular Scan (Custom Module Configuration)

Each custom module supports:

| Field | Description |
| --- | --- |
| name | Display name |
| type | file or url |
| method | GET, POST, PUT |
| url | Target endpoint |
| headers | Custom headers |
| bodyType | multipart, json, none |
| fileField | File field name in multipart |
| extraFields | Extra multipart fields |
| jsonTemplate | JSON template with placeholders |
| autoScan | Run automatically |
| filter | none, contains, regex |

Supported placeholders:

- {{fileUrl}}
- {{fileName}}
- {{url}}

---

## Built-in Whitelist and Blocklists

Base whitelist includes known domains (Discord, YouTube, GitHub, etc.) to reduce noise and unnecessary queries.

Active blocklists:

1. [FMHY](https://github.com/fmhy/FMHYFilterlist) Unsafe Sites Filterlist
2. User custom list.

## Disclaimer

- I'm not an expert in TypeScript; the plugin has a lot of bugs, and the code is inefficient in many places. I'd love for people to contribute, but always in a respectful way. You might think this project is silly, and I respect that, but I prefer to focus on the positive.

- I am not responsible for any misuse, damages, or consequences arising from the use of this plugin.

## More Images

<img width="599" height="621" alt="image" src="https://github.com/user-attachments/assets/f50acff9-89f2-4011-9d2a-6ec8e8a46bd6" />
<img width="597" height="788" alt="image" src="https://github.com/user-attachments/assets/266c1467-18a0-43b8-9729-7aafe0e7abf3" />
<img width="596" height="791" alt="image" src="https://github.com/user-attachments/assets/5b8fd4d0-70e8-40df-8d54-785e0c32eec1" />
<img width="605" height="796" alt="image" src="https://github.com/user-attachments/assets/5f80c6b0-f23b-4a04-92dc-ea2ecd5b56da" />
<img width="602" height="796" alt="image" src="https://github.com/user-attachments/assets/91a536ec-336e-45ca-a815-66304617bf5f" />





