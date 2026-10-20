/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";

import { AnalysisValue, safeToast } from "../../utils";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

export function isJarFile(fileName: string): boolean {
    return fileName.trim().toLowerCase().endsWith(".jar");
}

export async function analyzeFileWithRatterScanner(fileUrl: string, fileName: string, silent = false): Promise<AnalysisValue | null> {
    if (!isJarFile(fileName)) {
        if (!silent) safeToast("Ratter Scanner only supports .jar files.", "critical");
        return null;
    }

    if (!silent) safeToast(`Checking ${fileName} on Ratter Scanner...`);

    const { result, error } = await Native.queryRatterScanner(fileUrl);

    if (error || !result) {
        if (!silent) safeToast(`Ratter Scanner lookup failed: ${error ?? "unknown error"}`, "critical");
        return null;
    }

    const details: AnalysisValue["details"] = [];

    if (result.malicious) {
        details.push({ message: `[Ratter Scanner] [MALICIOUS] ${fileName} is a known malicious Minecraft file`, type: "malicious" });
    } else if (result.safe) {
        details.push({ message: `[Ratter Scanner] ${fileName} manually confirmed safe by staff`, type: "safe" });
    } else if (result.automated_safe) {
        const repo = result.githubInfo?.repoUrl ?? result.githubInfo?.projectName;
        details.push({
            message: `[Ratter Scanner] ${fileName} matches a trusted repository build${repo ? ` (${repo})` : ""}`,
            type: "safe"
        });
    } else {
        details.push({ message: `[Ratter Scanner] ${fileName} is unknown to the database`, type: "neutral" });
    }

    if (!silent) {
        if (result.malicious) {
            safeToast(`WARNING: ${fileName} is known Minecraft malware!`, "critical");
        } else if (result.safe || result.automated_safe) {
            safeToast(`${fileName} is known safe on Ratter Scanner`, "success");
        } else {
            safeToast(`${fileName} not found in Ratter Scanner database`);
        }
    }

    return { details, timestamp: Date.now() };
}
