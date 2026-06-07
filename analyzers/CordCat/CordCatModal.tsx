/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

interface StatementData {
    decision_provision?: string;
    category?: string;
    incompatible_content_ground?: string;
    incompatible_content_explanation?: string;
    category_specification_other?: string;
    decision_facts?: string;
    automated_detection?: string;
    application_date?: string;
    incompatible_content_illegal?: string;
}

interface BreachData {
    source: string;
    ip?: string;
    username?: string;
    discordname?: string;
    categories?: string[];
    date?: string;
    fields?: Record<string, string>;
}

interface IPGeoData {
    asn?: string;
    organization?: string;
    country?: string;
}

interface FivemResult {
    id: number;
    license?: string | null;
    license2?: string | null;
    steam?: string | null;
    name?: string | null;
    ip?: string | null;
    discord_id?: string | null;
    discord_name?: string | null;
    email?: string | null;
    source_file?: string | null;
    ip_asn?: IPGeoData | null;
}

interface ScoreSignal {
    key: string;
    label: string;
    detail?: string;
    points: number;
    kind: "good" | "risk";
}

interface BotInfo {
    score: number;
    level: string;
    isBot: boolean;
    reasons?: string[];
}

interface ScoreData {
    risk: number;
    level: string;
    signals?: ScoreSignal[];
    bot?: BotInfo;
}

interface MetaData {
    cached?: boolean;
    fetchedAt?: string;
    lastChecked?: string | null;
    changes?: unknown[];
}

interface BreachResponseData {
    results?: BreachData[];
    bySource?: Record<string, Record<string, string>[] | null>;
    ipGeo?: Record<string, IPGeoData>;
}

interface GuildTag {
    tag: string;
    identity_guild_id: string;
    identity_enabled: boolean;
    badge?: string;
}

interface UserInfo {
    id: string;
    username?: string;
    global_name?: string;
    discriminator?: string;
    avatar?: string;
    banner?: string;
    banner_color?: string | null;
    public_flags?: number;
    flags?: number;
    accent_color?: number | null;
    avatar_decoration_data?: unknown;
    collectibles?: unknown;
    display_name_styles?: unknown;
    clan?: GuildTag;
    primary_guild?: GuildTag;
}

const TEXT_NORMAL = "var(--text-normal, var(--header-primary, #dcddde))";
const TEXT_MUTED = "var(--text-muted, var(--header-secondary, #b5bac1))";

const RISK_COLORS: Record<string, string> = {
    low: "var(--status-positive)",
    medium: "var(--text-warning)",
    high: "var(--status-danger)",
    critical: "var(--status-danger)",
};

const SIGNAL_COLORS: Record<ScoreSignal["kind"], string> = {
    risk: "var(--status-danger)",
    good: "var(--status-positive)",
};

function fmtEnum(value: string | undefined, prefix: string) {
    return (value ?? "UNKNOWN").replace(prefix, "").replace(/_/g, " ");
}

function fmtDate(value: string | undefined | null) {
    return value ? String(value).slice(0, 10) : "—";
}

function fmtDateTime(value: string | undefined | null) {
    return value ? String(value).replace("T", " ").slice(0, 19) : "—";
}

function riskColor(level: string | undefined) {
    return RISK_COLORS[(level ?? "").toLowerCase()] ?? TEXT_MUTED;
}

function Tag({ children, color }: { children: React.ReactNode; color: string; }) {
    return (
        <span style={{ background: color, color: "#fff", borderRadius: 3, padding: "1px 6px", fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const }}>
            {children}
        </span>
    );
}

function Field({ label, value }: { label: string; value: string; }) {
    return (
        <div style={{ display: "flex", gap: 8, fontSize: 13, marginBottom: 2 }}>
            <span style={{ color: TEXT_MUTED, minWidth: 100, flexShrink: 0 }}>{label}</span>
            <span style={{ color: TEXT_NORMAL }}>{value}</span>
        </div>
    );
}

function SanctionCard({ s }: { s: StatementData; }) {
    return (
        <div style={{ borderLeft: "3px solid var(--status-danger)", background: "var(--background-secondary)", borderRadius: 4, padding: "8px 12px", marginBottom: 8 }}>
            <div style={{ display: "flex", gap: 5, flexWrap: "wrap" as const, marginBottom: 6 }}>
                <Tag color="var(--status-danger)">{fmtEnum(s.decision_provision, "DECISION_PROVISION_")}</Tag>
                <Tag color="var(--text-warning)">{fmtEnum(s.category, "STATEMENT_CATEGORY_")}</Tag>
                {s.incompatible_content_illegal === "Yes" && <Tag color="#7b0000">ILLEGAL</Tag>}
            </div>
            {s.incompatible_content_ground && <Field label="Rule broken" value={s.incompatible_content_ground} />}
            {s.incompatible_content_explanation && <Field label="Explanation" value={s.incompatible_content_explanation} />}
            {s.category_specification_other && <Field label="Sub-category" value={s.category_specification_other} />}
            {s.decision_facts && <Field label="Facts" value={s.decision_facts} />}
            {s.automated_detection && <Field label="Automated" value={s.automated_detection} />}
            <Field label="Applied" value={fmtDate(s.application_date)} />
        </div>
    );
}

function BreachCard({ b }: { b: BreachData; }) {
    return (
        <div style={{ borderLeft: "3px solid var(--text-warning)", background: "var(--background-secondary)", borderRadius: 4, padding: "8px 12px", marginBottom: 6 }}>
            <div style={{ fontWeight: 700, marginBottom: 4 }}>{b.source}</div>
            {b.ip && <Field label="IP" value={b.ip} />}
            {(b.username || b.discordname) && <Field label="Username" value={(b.username || b.discordname)!} />}
            {b.categories && b.categories.length > 0 && <Field label="Categories" value={b.categories.join(", ")} />}
            <Field label="Date" value={fmtDate(b.date)} />
        </div>
    );
}

function FivemCard({ r }: { r: FivemResult; }) {
    return (
        <div style={{ borderLeft: "3px solid var(--brand-experiment, #5865f2)", background: "var(--background-secondary)", borderRadius: 4, padding: "8px 12px", marginBottom: 6 }}>
            <div style={{ fontWeight: 700, marginBottom: 4 }}>{r.source_file ?? `Result #${r.id}`}</div>
            {r.name && <Field label="Name" value={r.name} />}
            {r.license && <Field label="License" value={r.license} />}
            {r.steam && <Field label="Steam" value={r.steam} />}
            {r.ip && <Field label="IP" value={r.ip} />}
            {r.discord_name && <Field label="Discord name" value={r.discord_name} />}
            {r.email && <Field label="Email" value={r.email} />}
            {r.ip_asn && (
                <Field label="IP location" value={[r.ip_asn.organization, r.ip_asn.country].filter(Boolean).join(" — ")} />
            )}
        </div>
    );
}

function SignalRow({ s }: { s: ScoreSignal; }) {
    const points = s.points >= 0 ? `+${s.points}` : String(s.points);
    return (
        <div style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 13, marginBottom: 4 }}>
            <Tag color={SIGNAL_COLORS[s.kind]}>{points}</Tag>
            <div>
                <span style={{ color: TEXT_NORMAL, fontWeight: 600 }}>{s.label}</span>
                {s.detail && <span style={{ color: TEXT_MUTED }}> — {s.detail}</span>}
            </div>
        </div>
    );
}

function SectionTitle({ children }: { children: React.ReactNode; }) {
    return (
        <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "0.06em", color: TEXT_MUTED, borderBottom: "1px solid var(--background-modifier-accent)", paddingBottom: 3, marginBottom: 8, marginTop: 4 }}>
            {children}
        </div>
    );
}

export function CordCatModal({ data }: { data: any; }) {
    const u: UserInfo = data.userInfo ?? {};
    const statements: StatementData[] = data.statements ?? [];
    const score: ScoreData | undefined = data.score;
    const meta: MetaData | undefined = data.meta;

    let breachResults: BreachData[] = [];
    let breachError: string | null = null;
    let ipGeo: Record<string, IPGeoData> = {};
    if (data.breach) {
        if (data.breach.success === false && data.breach.error) {
            breachError = `${data.breach.error.status}: ${data.breach.error.message}`;
        } else {
            const breachData: BreachResponseData | undefined = data.breach.data ?? data.breach;
            if (Array.isArray(breachData?.results)) {
                breachResults = breachData.results;
                ipGeo = breachData.ipGeo ?? {};
            }
        }
    }
    const breachCount: number = data.breach?.resultsCount ?? breachResults.length;

    const fivemResults: FivemResult[] = Array.isArray(data.fivem?.data?.results) ? data.fivem.data.results : [];
    const fivemTotal: number = data.fivem?.data?.total ?? fivemResults.length;

    const avatar = u.avatar
        ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.${u.avatar.startsWith("a_") ? "gif" : "png"}?size=80`
        : "https://cdn.discordapp.com/embed/avatars/0.png";

    const banner = u.banner
        ? `https://cdn.discordapp.com/banners/${u.id}/${u.banner}.${u.banner.startsWith("a_") ? "gif" : "png"}?size=480`
        : null;

    const handle = u.discriminator && u.discriminator !== "0"
        ? `${u.username}#${u.discriminator}`
        : `@${u.username}`;

    const guild = u.clan ?? u.primary_guild;
    const uniqueIPs = [...new Set(breachResults
        .map(b => b.ip)
        .filter((ip): ip is string => typeof ip === "string" && ip.length > 0)
    )];

    return (
        <div style={{ padding: "4px 2px", color: TEXT_NORMAL }}>

            {banner && (
                <img src={banner} alt="" style={{ width: "100%", height: 80, objectFit: "cover", borderRadius: 4, marginBottom: 10 }} />
            )}

            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                <img src={avatar} alt="" style={{ width: 56, height: 56, borderRadius: "50%", border: "3px solid var(--background-tertiary)", flexShrink: 0 }} />
                <div>
                    <div style={{ fontWeight: 800, fontSize: 16, color: "var(--white-500, #fff)" }}>{u.global_name || u.username || "Unknown"}</div>
                    <div style={{ color: TEXT_MUTED, fontSize: 13 }}>{handle}</div>
                    <div style={{ color: TEXT_MUTED, fontSize: 11, fontFamily: "var(--font-code)" }}>{u.id}</div>
                </div>
            </div>

            <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 14 }}>
                <Tag color={statements.length > 0 ? "var(--status-danger)" : "var(--status-positive)"}>
                    {statements.length > 0 ? `${statements.length} sanction${statements.length !== 1 ? "s" : ""}` : "No sanctions"}
                </Tag>
                <Tag color={breachCount > 0 ? "var(--text-warning)" : "var(--status-positive)"}>
                    {breachCount > 0 ? `${breachCount} breach${breachCount !== 1 ? "es" : ""}` : "No breaches"}
                </Tag>
                {score && (
                    <Tag color={riskColor(score.level)}>Risk {score.risk} ({score.level})</Tag>
                )}
                {score?.bot?.isBot && (
                    <Tag color="var(--status-danger)">Likely bot</Tag>
                )}
            </div>

            {score && (<>
                <SectionTitle>Risk Score</SectionTitle>
                <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 8 }}>
                    <div style={{ fontSize: 22, fontWeight: 800, color: riskColor(score.level) }}>{score.risk}</div>
                    <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: TEXT_NORMAL, textTransform: "capitalize" as const }}>{score.level} risk</div>
                        {score.bot && (
                            <div style={{ fontSize: 12, color: TEXT_MUTED }}>
                                Bot likelihood: <span style={{ color: TEXT_NORMAL }}>{score.bot.level}</span> ({score.bot.score}/100)
                            </div>
                        )}
                    </div>
                </div>
                {score.signals && score.signals.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                        {score.signals.map((s, i) => <SignalRow key={i} s={s} />)}
                    </div>
                )}
                {score.bot?.reasons && score.bot.reasons.length > 0 && (
                    <Field label="Bot reasons" value={score.bot.reasons.join(", ")} />
                )}
            </>)}

            <SectionTitle>User Info</SectionTitle>
            {u.global_name && <Field label="Display name" value={u.global_name} />}
            <Field label="Username" value={u.username ?? "—"} />
            <Field label="User ID" value={u.id} />
            <Field label="Public flags" value={String(u.public_flags ?? 0)} />
            {u.accent_color != null && <Field label="Accent color" value={`#${u.accent_color.toString(16).padStart(6, "0")}`} />}

            {guild && <>
                <SectionTitle>Guild Tag</SectionTitle>
                <Field label="Tag" value={`[${guild.tag}]`} />
                <Field label="Guild ID" value={guild.identity_guild_id} />
                <Field label="Enabled" value={guild.identity_enabled ? "Yes" : "No"} />
            </>}

            <SectionTitle>Sanctions ({statements.length})</SectionTitle>
            {statements.length === 0
                ? <div style={{ color: TEXT_MUTED, fontSize: 13, marginBottom: 8 }}>No sanctions on record.</div>
                : statements.map((s, i) => <SanctionCard key={i} s={s} />)
            }

            <SectionTitle>Data Breaches ({breachCount})</SectionTitle>
            {breachError ? (
                <div style={{ color: "var(--status-danger)", fontSize: 13, marginBottom: 8, padding: 8, background: "var(--background-secondary)", borderRadius: 4 }}>
                    Error fetching breach data: {breachError}
                </div>
            ) : uniqueIPs.length > 0 && (
                <div style={{ marginBottom: 8, fontSize: 13 }}>
                    <div style={{ color: TEXT_MUTED, marginBottom: 2 }}>Leaked IPs:</div>
                    {uniqueIPs.map((ip, i) => {
                        const geo = ipGeo[ip];
                        return (
                            <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline", marginBottom: 2 }}>
                                <code>{ip}</code>
                                {geo && (
                                    <span style={{ color: TEXT_MUTED, fontSize: 12 }}>
                                        {[geo.organization, geo.asn, geo.country].filter(Boolean).join(" • ")}
                                    </span>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
            {breachError ? null : breachResults.length === 0
                ? <div style={{ color: TEXT_MUTED, fontSize: 13 }}>No breach data found.</div>
                : breachResults.map((b, i) => <BreachCard key={i} b={b} />)
            }

            {data.fivem && (<>
                <SectionTitle>FiveM Leaks ({fivemTotal})</SectionTitle>
                {fivemResults.length === 0
                    ? <div style={{ color: TEXT_MUTED, fontSize: 13 }}>No FiveM data found.</div>
                    : fivemResults.map((r, i) => <FivemCard key={i} r={r} />)
                }
            </>)}

            {meta && (
                <div style={{ marginTop: 14, paddingTop: 8, borderTop: "1px solid var(--background-modifier-accent)", display: "flex", flexWrap: "wrap" as const, gap: 12, fontSize: 11, color: TEXT_MUTED }}>
                    <span>{meta.cached ? "Served from cache" : "Freshly fetched"}</span>
                    {meta.fetchedAt && <span>Fetched: {fmtDateTime(meta.fetchedAt)}</span>}
                    {meta.lastChecked && <span>Last checked: {fmtDateTime(meta.lastChecked)}</span>}
                </div>
            )}

        </div>
    );
}
