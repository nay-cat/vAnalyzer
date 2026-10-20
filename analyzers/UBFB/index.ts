/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";

import { formatTimestamp } from "../../components/modalPrimitives";
import { AnalysisValue, safeToast } from "../../utils";
import { ReputationField, ReputationSection } from "../ReputationModal";

export { UBFB_REASONS } from "./reasons";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

export async function analyzeUserWithUbfb(userId: string, userName: string, silent = false): Promise<AnalysisValue | null> {
    if (!silent) safeToast(`Checking ${userName} on UBFB...`);

    const { blacklisted, entry, error } = await Native.queryUbfb(userId);

    if (error) {
        if (!silent) safeToast(`UBFB lookup failed: ${error}`, "critical");
        return null;
    }

    const details: AnalysisValue["details"] = [];

    if (blacklisted) {
        const reason = entry?.reason ?? "unspecified";
        const days = entry?.punishmentDays;
        details.push({
            message: `[UBFB] [BLACKLISTED] ${userName}: ${reason}${days ? ` (${days} days)` : ""}`,
            type: "malicious"
        });
    } else {
        details.push({ message: `[UBFB] ${userName} is not on the blacklist`, type: "safe" });
    }

    if (!silent) {
        if (blacklisted) {
            safeToast(`WARNING: ${userName} is blacklisted on UBFB!`, "critical");
        } else {
            safeToast(`${userName} is not on the UBFB blacklist`, "success");
        }
    }

    return { details, timestamp: Date.now() };
}

export async function reportUserToUbfb(
    userId: string,
    reason: string,
    proofs: string[],
    authorId: string,
    authorUsername: string
): Promise<boolean> {
    safeToast("Submitting report to UBFB...");

    const { ok, error } = await Native.submitUbfbReport({
        userId,
        reason,
        authorId,
        authorUsername,
        proofs
    });

    if (!ok) {
        safeToast(`UBFB report failed: ${error ?? "unknown error"}`, "critical");
        return false;
    }

    safeToast("Report submitted to UBFB for staff review", "success");
    return true;
}

/** Proofs come back as relative paths such as "proofs/<uuid>.png". */
function proofUrl(proof: string): string {
    if (/^https?:\/\//i.test(proof)) return proof;
    return `https://ubfb-api.theindiebrand.es/cdn/${proof.replace(/^\/+/, "")}`;
}

/** Structured view of the lookup, for the reputation modal. */
export async function describeUbfb(userId: string, userName: string): Promise<ReputationSection> {
    const { blacklisted, entry, error } = await Native.queryUbfb(userId);

    if (error) {
        return { service: "UBFB", verdict: "error", summary: "Lookup failed", error };
    }

    if (!blacklisted) {
        return { service: "UBFB", verdict: "safe", summary: `${userName} is not on the blacklist` };
    }

    const fields: ReputationField[] = [];
    if (entry?.reason) fields.push({ label: "Reason", value: entry.reason });
    if (entry?.status) fields.push({ label: "Status", value: entry.status });
    if (entry?.punishmentDays) fields.push({ label: "Punishment", value: `${entry.punishmentDays} days` });

    const created = formatTimestamp(entry?.createdAt);
    if (created) fields.push({ label: "Reported", value: created });

    const updated = formatTimestamp(entry?.updatedAt);
    if (updated && updated !== created) fields.push({ label: "Updated", value: updated });

    if (entry?.authorUsername) fields.push({ label: "Reported by", value: entry.authorUsername });
    if (entry?.intermediaryUsername && entry.intermediaryUsername !== entry.authorUsername) {
        fields.push({ label: "Via", value: entry.intermediaryUsername });
    }

    for (const proof of entry?.proofs ?? []) {
        fields.push({ label: "Proof", value: proofUrl(proof), link: true });
    }

    return {
        service: "UBFB",
        verdict: "malicious",
        summary: "Listed on the shared blacklist",
        fields
    };
}
