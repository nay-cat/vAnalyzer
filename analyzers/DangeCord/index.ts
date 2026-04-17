import { User } from "@vencord/discord-types";
import { PluginNative } from "@utils/types";
import { showToast, Toasts } from "@webpack/common";

import { settings } from "../../settings";
import { AnalysisValue } from "../../utils";

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
        message: `[DangeCord] Status: ${statusLabel} | Reports: ${reports}`,
        type
    });

    if (data.votes) {
        details.push({
            message: `[DangeCord] Votes: ${data.votes.upvotes ?? 0} Up / ${data.votes.downvotes ?? 0} Down`,
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
        if (!silent) showToast("Looking up the user profile on DangeCord...", Toasts.Type.MESSAGE);

        const apiKey = settings.store.dangecordApiKey;
        const dcProfile = await Native.lookupDangeCordProfile(apiKey, memberId);

        if (dcProfile.status !== 200) {
            if (!silent) showToast(`DangeCord lookup failed: ${dcProfile.status}`, Toasts.Type.FAILURE);
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
