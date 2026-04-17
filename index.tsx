/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./style/styles.css";

import { findGroupChildrenByChildId, NavContextMenuPatchCallback } from "@api/ContextMenu";
import definePlugin from "@utils/types";
import { Message } from "@vencord/discord-types";
import { Alerts, Menu } from "@webpack/common";

import { LinkIcon, OpenExternalIcon, SafetyIcon } from "@components/Icons";

import { AnalysisAccessory, handleAnalysis } from "./AnalysisAccesory";
import { getThreat } from "./threatStore";
import { lookDangeCord } from "./analyzers/DangeCord";
import { analyzeDiscordInvite, isDiscordInvite } from "./analyzers/DiscordInvite";
import { analyzeFileWithHybridAnalysis, analyzeUrlWithHybridAnalysis } from "./analyzers/HybridAnalysis";
import { analyzeWithCertPL } from "./analyzers/CertPL";
import { analyzeWithCrtSh } from "./analyzers/CrtSh";
import { analyzeWithFishFish } from "./analyzers/FishFish";
import { analyzeWithSucuri } from "./analyzers/Sucuri";
import { analyzeWithVirusTotal } from "./analyzers/VirusTotal";
import { analyzeWithWhereGoes } from "./analyzers/WhereGoes";
import { runModularScan } from "./analyzers/ModularScan";
import { autoAnalyzeMessage, extractUrlsFromMessage, manualAnalyzeUrls } from "./autoAnalyze";
import { settings } from "./settings";
import { getModulesSync } from "./modularScanStore";
import { initFilters, setCustomWhitelist, setCustomBlocklist } from "./urlFilter";
import { extractCdnFileUrls, truncateUrl } from "./utils";

async function genericAnalyze(messageId: string, url: string, analyzer: (url: string, silent: boolean) => Promise<any>, silent = false) {
    const result = await analyzer(url, silent);
    if (result) {
        handleAnalysis(messageId, result, url);
    }
}

async function genericAnalyzeFile(messageId: string, fileUrl: string, fileName: string, analyzer: (url: string, name: string, silent: boolean) => Promise<any>, silent = false) {
    const result = await analyzer(fileUrl, fileName, silent);
    if (result) {
        handleAnalysis(messageId, result, fileUrl);
    }
}

async function analyzeUser(messageId: string | undefined, user: any, silent = false) {
    const result = await lookDangeCord(user, silent);
    if (result) {
        if (messageId) {
            handleAnalysis(messageId, result);
        } else {
            Alerts.show({
                title: "DangeCord Analysis",
                body: (
                    <div className="vc-analyzer-modal">
                        {result.details.map((detail, i) => (
                            <div key={i} style={{ marginBottom: "4px" }}>
                                • {detail.message}
                            </div>
                        ))}
                    </div>
                ),
                confirmText: "Close"
            });
        }
    }
}

function openExternal(url: string) {
    VencordNative.native.openExternal(url);
}

function getUserSearchLinks(userId: string) {
    const encodedId = encodeURIComponent(userId);
    return [
        { id: "top-gg", label: "top.gg", url: `https://top.gg/user/${encodedId}` },
        { id: "discordhub", label: "DiscordHub", url: `https://discordhub.com/profile/${encodedId}` }
    ];
}

function getServerSearchLinks(guildId: string) {
    const encodedId = encodeURIComponent(guildId);
    return [
        { id: "disboard", label: "Disboard", url: `https://disboard.org/es/server/${encodedId}` },
        { id: "discordservers", label: "DiscordServers", url: `https://discordservers.com/server/${encodedId}` }
    ];
}

const urlAnalyzers = [
    { id: "auto-url-checks", label: "Run all automatic checks", fn: null as null },
    { id: "wg", label: "Trace URL with WhereGoes", fn: analyzeWithWhereGoes },
    { id: "crtsh", label: "Check certificates (crt.sh)", fn: analyzeWithCrtSh },
    { id: "certpl", label: "Check blocklist (CERT.PL)", fn: analyzeWithCertPL },
    { id: "fishfish", label: "Check phishing (FishFish)", fn: analyzeWithFishFish },
    { id: "sucuri", label: "Check reputation (Sucuri)", fn: analyzeWithSucuri },
    { id: "ha-url", label: "Scan URL (Hybrid Analysis)", fn: analyzeUrlWithHybridAnalysis },
];

const fileAnalyzers = [
    { id: "vt", label: "Scan file with VirusTotal", fn: (msgId: string, url: string, _name: string) => genericAnalyze(msgId, url, (u, s) => analyzeWithVirusTotal(msgId, u, s)) },
    { id: "ha-file", label: "Scan file with Hybrid Analysis", fn: (msgId: string, url: string, name: string) => genericAnalyzeFile(msgId, url, name, analyzeFileWithHybridAnalysis) },
];

const messageCtxPatch: NavContextMenuPatchCallback = (children, { message }: { message: Message; }) => {
    const hasAttachments = !!message.attachments?.length;
    const urls = extractUrlsFromMessage(message);
    const inviteUrls = urls.filter(isDiscordInvite);
    const normalUrls = urls.filter(u => !isDiscordInvite(u));
    const cdnFiles = extractCdnFileUrls(normalUrls);
    const hasUrls = normalUrls.length > 0;
    const hasCdnFiles = cdnFiles.length > 0;
    const hasInvites = inviteUrls.length > 0;

    const group = findGroupChildrenByChildId("copy-text", children)
        ?? findGroupChildrenByChildId("copy-link", children)
        ?? children;

    group.push(
        <Menu.MenuItem
            id="vc-analyze-dangecord"
            label="Scan author with DangeCord"
            icon={SafetyIcon}
            action={() => analyzeUser(message.id, message.author)}
        />
    );

    if (!hasAttachments && !hasUrls && !hasInvites && !hasCdnFiles) return;

    if (hasAttachments) {
        for (const analyzer of fileAnalyzers) {
            if (message.attachments.length === 1) {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                        action={() => analyzer.fn(message.id, message.attachments[0].url, message.attachments[0].filename)}
                    />
                );
            } else {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                    >
                        {message.attachments.map((attachment, i) => (
                            <Menu.MenuItem
                                id={`vc-analyze-${analyzer.id}-${i}`}
                                key={attachment.id}
                                label={attachment.filename}
                                action={() => analyzer.fn(message.id, attachment.url, attachment.filename)}
                            />
                        ))}
                    </Menu.MenuItem>
                );
            }
        }
    }

    if (hasCdnFiles) {
        for (const analyzer of fileAnalyzers) {
            if (cdnFiles.length === 1) {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-cdn-${analyzer.id}`}
                        label={`${analyzer.label} (${cdnFiles[0].fileName})`}
                        icon={SafetyIcon}
                        action={() => analyzer.fn(message.id, cdnFiles[0].url, cdnFiles[0].fileName)}
                    />
                );
            } else {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-cdn-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                    >
                        {cdnFiles.map((file, i) => (
                            <Menu.MenuItem
                                id={`vc-analyze-cdn-${analyzer.id}-${i}`}
                                key={file.url}
                                label={file.fileName}
                                action={() => analyzer.fn(message.id, file.url, file.fileName)}
                            />
                        ))}
                    </Menu.MenuItem>
                );
            }
        }
    }

    if (hasUrls) {
        const primaryUrl = normalUrls[0];
        group.push(
            <Menu.MenuItem
                id="vc-analyze-url-group"
                label="Analyze URL"
                icon={LinkIcon}
            >
                {urlAnalyzers.map(analyzer => {
                    const action = analyzer.fn
                        ? (url: string) => genericAnalyze(message.id, url, analyzer.fn!)
                        : (url: string) => manualAnalyzeUrls(message, [url]);

                    return (
                        <Menu.MenuItem
                            id={`vc-analyze-${analyzer.id}`}
                            key={analyzer.id}
                            label={analyzer.label}
                            action={() => action(primaryUrl)}
                        >
                            {normalUrls.length > 1 && normalUrls.map((url, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-${analyzer.id}-${i}`}
                                    key={url}
                                    label={truncateUrl(url)}
                                    action={() => action(url)}
                                />
                            ))}
                        </Menu.MenuItem>
                    );
                })}
            </Menu.MenuItem>
        );
    }

    if (hasInvites) {
        const analyzeInvite = (url: string) => analyzeDiscordInvite(url).then(r => r && handleAnalysis(message.id, r));

        if (inviteUrls.length === 1) {
            group.push(
                <Menu.MenuItem
                    id="vc-analyze-invite"
                    label="Analyze Discord invite"
                    icon={OpenExternalIcon}
                    action={() => analyzeInvite(inviteUrls[0])}
                />
            );
        } else {
            group.push(
                <Menu.MenuItem
                    id="vc-analyze-invite"
                    label="Analyze Discord invite"
                    icon={OpenExternalIcon}
                >
                    {inviteUrls.map((url, i) => (
                        <Menu.MenuItem
                            id={`vc-analyze-invite-${i}`}
                            key={url}
                            label={truncateUrl(url)}
                            action={() => analyzeInvite(url)}
                        />
                    ))}
                </Menu.MenuItem>
            );
        }
    }

    const modularModules = getModulesSync();
    if (modularModules.length > 0) {
        const analyzeModular = async (module: any, fileUrl: string, fileName: string) => {
            const result = await runModularScan(module, fileUrl, fileName);
            if (result) handleAnalysis(message.id, result, fileUrl);
        };

        group.push(
            <Menu.MenuItem
                id="vc-analyze-modular-group"
                label="Modular Scan"
                icon={SafetyIcon}
            >
                {modularModules.map(module => {
                    const isUrlMatch = module.type === "url" && hasUrls;
                    const isFileMatch = module.type === "file" && hasAttachments;

                    if (!isUrlMatch && !isFileMatch) return null;

                    return (
                        <Menu.MenuItem
                            id={`vc-analyze-modular-${module.id}`}
                            key={module.id}
                            label={module.name}
                            action={() => {
                                if (isUrlMatch) analyzeModular(module, urls[0], "");
                                else analyzeModular(module, message.attachments[0].url, message.attachments[0].filename);
                            }}
                        >
                            {isUrlMatch && urls.length > 1 && urls.map((url, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-modular-${module.id}-${i}`}
                                    key={url}
                                    label={truncateUrl(url)}
                                    action={() => analyzeModular(module, url, "")}
                                />
                            ))}
                            {isFileMatch && message.attachments.length > 1 && message.attachments.map((attachment, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-modular-${module.id}-${i}`}
                                    key={attachment.id}
                                    label={attachment.filename}
                                    action={() => analyzeModular(module, attachment.url, attachment.filename)}
                                />
                            ))}
                        </Menu.MenuItem>
                    );
                })}
            </Menu.MenuItem>
        );
    }
};

const userContextPatch: NavContextMenuPatchCallback = (children, { user }: { user: any; }) => {
    if (!user) return;

    if (settings.store.enableOsintSearchShortcuts) {
        const links = getUserSearchLinks(user.id);
        children.push(
            <Menu.MenuItem
                id="vc-analyze-search-user"
                label="Search User"
                icon={OpenExternalIcon}
            >
                {links.map(link => (
                    <Menu.MenuItem
                        id={`vc-analyze-search-user-${link.id}`}
                        key={link.id}
                        label={link.label}
                        action={() => openExternal(link.url)}
                    />
                ))}
            </Menu.MenuItem>
        );
    }

    children.push(
        <Menu.MenuItem
            id="vc-analyze-user-dangecord"
            label="Scan with DangeCord"
            icon={SafetyIcon}
            action={() => analyzeUser(undefined, user)}
        />
    );
};

const guildContextPatch: NavContextMenuPatchCallback = (children, { guild }: { guild: { id: string; }; }) => {
    if (!guild || !settings.store.enableOsintSearchShortcuts) return;

    const group = findGroupChildrenByChildId("privacy", children) ?? children;
    const links = getServerSearchLinks(guild.id);
    group.push(
        <Menu.MenuItem
            id="vc-analyze-search-server"
            label="Search Server"
            icon={OpenExternalIcon}
        >
            {links.map(link => (
                <Menu.MenuItem
                    id={`vc-analyze-search-server-${link.id}`}
                    key={link.id}
                    label={link.label}
                    action={() => openExternal(link.url)}
                />
            ))}
        </Menu.MenuItem>
    );
};

export default definePlugin({
    name: "vAnalyzer",
    description: "Analyze message attachments, trace URLs, check certificates, avoid scams and more.",
    authors: [{ name: "nay-cat", id: 1159977353661919363n }],
    settings,

    async start() {
        await initFilters();

        // sync custom whitelist/blocklist from settings
        const wl = settings.store.customWhitelist;
        if (wl) setCustomWhitelist(wl.split(",").map(s => s.trim()).filter(Boolean));

        const bl = settings.store.customBlocklist;
        if (bl) setCustomBlocklist(bl.split(",").map(s => s.trim()).filter(Boolean));
    },

    patches: [
        // intercept link clicks to warn about flagged URLs
        // NOT WORKING
        // intercept file downloads to warn about flagged files
        // NOT WORKING
    ],

    handleLinkClick(data: { href: string; }) {
        if (!data?.href || !settings.store.warnOnLinkClick) return false;

        const threat = getThreat(data.href);
        if (!threat) return false;

        return new Promise<boolean>(resolve => {
            let resolved = false;
            const done = (block: boolean) => {
                if (resolved) return;
                resolved = true;
                resolve(block);
            };

            const isMalicious = threat.level === "malicious";

            let title: string;
            if (isMalicious) {
                title = "\u26a0\ufe0f Malicious Link Detected";
            } else {
                title = "\u26a0\ufe0f Suspicious Link Detected";
            }

            let confirmColor: string;
            if (isMalicious) {
                confirmColor = "var(--button-danger-background)";
            } else {
                confirmColor = "var(--button-outline-danger-text)";
            }

            Alerts.show({
                title,
                body: (
                    <div>
                        <p style={{ marginBottom: "8px" }}>
                            This link has been flagged as <strong>{threat.level}</strong> by vAnalyzer:
                        </p>
                        <div style={{ padding: "8px", background: "var(--background-secondary)", borderRadius: "4px", marginBottom: "8px" }}>
                            <code>{data.href}</code>
                        </div>
                        <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                            {threat.reasons.map((r, i) => (
                                <div key={i}>{"\u2022"} {r}</div>
                            ))}
                        </div>
                    </div>
                ),
                confirmText: "Open Anyway",
                cancelText: "Cancel",
                confirmColor,
                onConfirm: () => done(false),
                onCancel: () => done(true),
                onCloseCallback: () => done(true)
            });
        });
    },

    handleFileDownload(url: string) {
        if (!url || !settings.store.warnOnFileDownload) return false;

        const threat = getThreat(url);
        if (!threat) return false;

        return true;
    },

    flux: {
        MESSAGE_CREATE({ message, optimistic }: { message: Message; optimistic: boolean; }) {
            if (optimistic) return;
            autoAnalyzeMessage(message);
        }
    },

    contextMenus: {
        "message": messageCtxPatch,
        "user-context": userContextPatch,
        "guild-context": guildContextPatch,
        "guild-header-popout": guildContextPatch
    },

    renderMessageAccessory: props => {
        autoAnalyzeMessage(props.message);
        return <AnalysisAccessory message={props.message} />;
    },
});
