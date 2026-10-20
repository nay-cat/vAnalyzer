/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";
import { User } from "@vencord/discord-types";

import { settings } from "../../settings";
import { AnalysisValue, safeToast } from "../../utils";
import { ReputationField, ReputationSection } from "../ReputationModal";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;
const profileCache = new Map<string, any>();
const inFlightLookups = new Map<string, Promise<any | null>>();

function buildDetails(data: any): AnalysisValue["details"] {
    const details: AnalysisValue["details"] = [];

    const isBlacklisted = !!data.badges?.blacklisted;
    const reports = data.reports ?? 0;

    let type: "malicious" | "suspicious" | "safe";
    if (isBlacklisted) {
        type = "malicious";
    } else if (reports > 0) {
        type = "suspicious";
    } else {
        type = "safe";
    }

    let statusLabel: string;
    if (isBlacklisted) {
        statusLabel = "BLACKLISTED";
    } else {
        statusLabel = "Clean";
    }

    details.push({
        message: `[Dangercord] Status: ${statusLabel} | Reports: ${reports}`,
        type
    });

    if (data.votes) {
        details.push({
            message: `[Dangercord] Votes: ${data.votes.upvotes ?? 0} Up / ${data.votes.downvotes ?? 0} Down`,
            type: "neutral"
        });
    }

    return details;
}

export async function lookDangeCord(user: User, silent = false): Promise<AnalysisValue | null> {
    const memberId = user.id;

    const cached = profileCache.get(memberId);
    if (cached) {
        return {
            details: buildDetails(cached),
            timestamp: Date.now()
        };
    }

    const pending = inFlightLookups.get(memberId);
    if (pending) {
        const pendingData = await pending;
        if (!pendingData) return null;
        return {
            details: buildDetails(pendingData),
            timestamp: Date.now()
        };
    }

    const lookup = (async () => {
        if (!silent) safeToast("Looking up the user profile on Dangercord...");

        const apiKey = settings.store.dangecordApiKey;
        const dcProfile = await Native.lookupDangeCordProfile(apiKey, memberId);

        if (dcProfile.status !== 200) {
            if (!silent) safeToast(`Dangercord lookup failed: ${dcProfile.status}`, "critical");
            return null;
        }

        profileCache.set(memberId, dcProfile.data);
        return dcProfile.data;
    })();

    inFlightLookups.set(memberId, lookup);

    try {
        const data = await lookup;
        if (!data) return null;

        return {
            details: buildDetails(data),
            timestamp: Date.now()
        };
    } finally {
        inFlightLookups.delete(memberId);
    }
}

/** Adapter matching the shared user-reputation service signature. */
export function analyzeUserWithDangercord(userId: string, _userName: string, silent = false): Promise<AnalysisValue | null> {
    return lookDangeCord({ id: userId } as User, silent);
}

/** Structured view of the lookup, for the reputation modal. */
export async function describeDangercord(userId: string, userName: string): Promise<ReputationSection> {
    const result = await lookDangeCord({ id: userId } as User, true);

    if (!result) {
        return { service: "Dangercord", verdict: "error", summary: "Lookup failed", error: "Could not reach Dangercord" };
    }

    const data = profileCache.get(userId);
    const blacklisted = !!data?.badges?.blacklisted;
    const reports = data?.reports ?? 0;

    const fields: ReputationField[] = [];
    fields.push({ label: "Status", value: blacklisted ? "Blacklisted" : "Clean" });
    fields.push({ label: "Reports", value: String(reports) });

    if (data?.votes) {
        fields.push({
            label: "Votes",
            value: `${data.votes.upvotes ?? 0} up / ${data.votes.downvotes ?? 0} down`
        });
    }

    let verdict: ReputationSection["verdict"];
    let summary: string;
    if (blacklisted) {
        verdict = "malicious";
        summary = "Blacklisted on Dangercord";
    } else if (reports > 0) {
        verdict = "suspicious";
        summary = `${reports} report(s) on record`;
    } else {
        verdict = "safe";
        summary = `${userName} is clean`;
    }

    return { service: "Dangercord", verdict, summary, fields };
}
