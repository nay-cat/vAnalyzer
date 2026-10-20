/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";

import { formatTimestamp } from "../../components/modalPrimitives";
import { AnalysisValue, safeToast } from "../../utils";
import { ReputationField, ReputationSection } from "../ReputationModal";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

export async function analyzeUserWithXnProtect(userId: string, userName: string, silent = false): Promise<AnalysisValue | null> {
    if (!silent) safeToast(`Checking ${userName} on XN Protect...`);

    const { ban, error } = await Native.queryXnProtect(userId);

    if (error || !ban) {
        if (!silent) safeToast(`XN Protect lookup failed: ${error ?? "unknown error"}`, "critical");
        return null;
    }

    const details: AnalysisValue["details"] = [];

    if (ban.banglobal) {
        const reason = ban.reason?.replace(/^\[XN PROTECT\]:\s*/i, "").trim() || "unspecified";
        const since = formatTimestamp(ban.dates?.since);
        const expires = formatTimestamp(ban.dates?.expires);

        let suffix = "";
        if (since) suffix += ` | since ${since}`;
        if (expires) suffix += ` | expires ${expires}`;

        details.push({
            message: `[XN Protect] [GLOBAL BAN] ${userName}: ${reason}${suffix}`,
            type: "malicious"
        });

        if (ban.proof) {
            details.push({ message: `[XN Protect] Proof: ${ban.proof}`, type: "neutral" });
        }
    } else {
        details.push({ message: `[XN Protect] ${userName} has no global ban`, type: "safe" });
    }

    if (!silent) {
        if (ban.banglobal) {
            safeToast(`WARNING: ${userName} has an XN Protect global ban!`, "critical");
        } else {
            safeToast(`${userName} has no XN Protect global ban`, "success");
        }
    }

    return { details, timestamp: Date.now() };
}

export async function describeXnProtect(userId: string, userName: string): Promise<ReputationSection> {
    const { ban, error } = await Native.queryXnProtect(userId);

    if (error || !ban) {
        return { service: "XN Protect", verdict: "error", summary: "Lookup failed", error: error ?? "unknown error" };
    }

    if (!ban.banglobal) {
        return { service: "XN Protect", verdict: "safe", summary: `${userName} has no global ban` };
    }

    const fields: ReputationField[] = [];

    const reason = ban.reason?.replace(/^\[XN PROTECT\]:\s*/i, "").trim();
    if (reason) fields.push({ label: "Reason", value: reason });

    const since = formatTimestamp(ban.dates?.since);
    if (since) fields.push({ label: "Banned since", value: since });

    const expires = formatTimestamp(ban.dates?.expires);
    fields.push({ label: "Expires", value: expires ?? "Never" });

    if (ban.proof) fields.push({ label: "Proof", value: ban.proof, link: true });

    return {
        service: "XN Protect",
        verdict: "malicious",
        summary: "Global ban on record",
        fields
    };
}
