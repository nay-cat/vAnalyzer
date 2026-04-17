/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";
import { showToast, Toasts } from "@webpack/common";

import { settings } from "../../settings";
import { AnalysisValue } from "../../utils";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

function buildDetails(stats: any): AnalysisValue["details"] {
    const details: AnalysisValue["details"] = [];

    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    if (total === 0) {
        details.push({ message: "[VT] No analysis results available", type: "neutral" });
        return details;
    }

    let type: "malicious" | "suspicious" | "safe";
    if (stats.malicious > 0) {
        type = "malicious";
    } else if (stats.suspicious > 0) {
        type = "suspicious";
    } else {
        type = "safe";
    }
    details.push({
        message: `[VT] Engines: ${stats.malicious} mal / ${stats.suspicious} sus / ${stats.harmless + stats.undetected} safe`,
        type
    });

    return details;
}

async function waitForVirusTotalReport(apiKey: string, analysisId: string, silent: boolean): Promise<any | null> {
    for (let i = 0; i < 8; i++) {
        if (i > 0) {
            await new Promise(resolve => setTimeout(resolve, 2500));
        }

        const reportResult = await Native.getVirusTotalFileReport(apiKey, analysisId);
        if (reportResult.status === 200 && reportResult.data) {
            return reportResult.data;
        }

        if (!silent && i === 0) {
            showToast("VirusTotal is still processing the file. Waiting for report...", Toasts.Type.MESSAGE);
        }
    }

    return null;
}

export async function analyzeWithVirusTotal(messageId: string, url: string, silent = false): Promise<AnalysisValue | null> {
    const apiKey = settings.store.virusTotalApiKey?.trim();
    const lookupFirst = !apiKey || settings.store.virusTotalLookupBeforeUpload;

    if (lookupFirst) {
        if (!silent) showToast("Looking up file on VirusTotal...", Toasts.Type.MESSAGE);

        const lookup = await Native.lookupVirusTotalFile(url);

        /*if (!silent) {
            showToast(`SHA-256: ${lookup.sha256 ?? "error"}`, Toasts.Type.MESSAGE);
            showToast(`VT status: ${lookup.status} | data: ${!!lookup.data}`, Toasts.Type.MESSAGE);
        }*/

        if (lookup.status === 200 && lookup.data) {
            const stats = lookup.data?.data?.attributes?.last_analysis_stats;
            if (stats) {
                if (!silent) showToast(`Found! mal:${stats.malicious} sus:${stats.suspicious} safe:${stats.harmless + stats.undetected}`, Toasts.Type.SUCCESS);
                return { details: buildDetails(stats), timestamp: Date.now() };
            }
        }

        // NEED APIKEY TO UPLOAD, FILE NOT FOUND
        if (!apiKey) {
            if (!silent) showToast("File not found on VirusTotal. Set an API key in settings to upload & scan.", Toasts.Type.FAILURE);
            return null;
        }

        if (!silent) showToast("File not cached. Uploading to VirusTotal...", Toasts.Type.MESSAGE);
    } else if (!silent) {
        showToast("Uploading file to VirusTotal...", Toasts.Type.MESSAGE);
    }

    const uploadResult = await Native.makeVirusTotalRequest(apiKey, url);

    if (uploadResult.status !== 200) {
        if (!silent) showToast("Failed to upload file to VirusTotal.", Toasts.Type.FAILURE);
        return null;
    }

    const analysisId = uploadResult.analysisId;
    if (!analysisId) {
        if (!silent) showToast("Could not get analysis ID from VirusTotal.", Toasts.Type.FAILURE);
        return null;
    }

    if (!silent) showToast("Fetching VirusTotal report...", Toasts.Type.MESSAGE);

    const reportData = await waitForVirusTotalReport(apiKey, analysisId, silent);
    if (!reportData) {
        if (!silent) {
            showToast("VirusTotal analysis is queued. Try again in a few seconds.", Toasts.Type.MESSAGE);
        }
        return {
            details: [{ message: "[VT] File uploaded successfully. Analysis is still pending.", type: "neutral" }],
            timestamp: Date.now()
        };
    }

    const stats = reportData?.data?.attributes?.last_analysis_stats;
    if (!stats) {
        if (!silent) showToast("Could not parse VirusTotal report.", Toasts.Type.FAILURE);
        return null;
    }

    return { details: buildDetails(stats), timestamp: Date.now() };
}
