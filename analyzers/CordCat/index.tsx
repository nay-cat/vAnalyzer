/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";
import { Modal, openModal, React } from "@webpack/common";

import { settings } from "../../settings";
import { AnalysisValue, safeToast } from "../../utils";
import { ReputationField, ReputationSection } from "../ReputationModal";
import { CordCatModal } from "./CordCatModal";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

export async function analyzeUserWithCordCat(userId: string, username: string): Promise<void> {
    const apiKey = settings.store.cordCatApiKey?.trim();
    if (!apiKey) {
        safeToast("CordCat requires an API key. Set it in vAnalyzer settings.", "critical");
        return;
    }

    safeToast(`Querying CordCat for ${username}...`);

    const result = await Native.queryCordCat(userId, apiKey);

    if (result.status !== 200) {
        safeToast(`CordCat lookup failed: HTTP ${result.status}`, "critical");
        return;
    }

    const { data } = result;
    const statements: any[] = data.statements ?? [];
    const breachCount: number = data.breach?.resultsCount ?? 0;

    const parts: string[] = [];
    if (statements.length > 0) parts.push(`${statements.length} sanction${statements.length !== 1 ? "s" : ""}`);
    if (breachCount > 0) parts.push(`${breachCount} breach${breachCount !== 1 ? "es" : ""}`);
    const suffix = parts.length > 0 ? ` — ${parts.join(", ")}` : "";

    const title = `CordCat: ${data.userInfo?.global_name || username}${suffix}`;

    openModal(modalProps => (
        <Modal
            {...modalProps}
            size="md"
            title={title}
            actions={[{ text: "Close", variant: "secondary", onClick: modalProps.onClose }]}
        >
            <CordCatModal data={data} />
        </Modal>
    ));
}

/** Runs the lookup and returns the raw payload, or null on failure. */
async function fetchCordCat(userId: string): Promise<any | null> {
    const apiKey = settings.store.cordCatApiKey?.trim();
    if (!apiKey) return null;

    const result = await Native.queryCordCat(userId, apiKey);
    if (result.status !== 200) return null;

    return result.data;
}

/** Structured view of the lookup, for the reputation modal. */
export async function describeCordCat(userId: string, userName: string): Promise<ReputationSection> {
    const apiKey = settings.store.cordCatApiKey?.trim();
    if (!apiKey) {
        return { service: "CordCat", verdict: "error", summary: "No API key", error: "Set a CordCat API key in vAnalyzer settings." };
    }

    const data = await fetchCordCat(userId);
    if (!data) {
        return { service: "CordCat", verdict: "error", summary: "Lookup failed", error: "Could not reach CordCat" };
    }

    const statements: any[] = data.statements ?? [];
    const breachCount: number = data.breach?.resultsCount ?? data.breach?.data?.results?.length ?? 0;
    const fivemTotal: number = data.fivem?.data?.total ?? 0;
    const { score } = data;

    const fields: ReputationField[] = [];
    fields.push({ label: "Sanctions", value: String(statements.length) });
    fields.push({ label: "Breaches", value: String(breachCount) });
    if (fivemTotal > 0) fields.push({ label: "FiveM records", value: String(fivemTotal) });
    if (score) fields.push({ label: "Risk", value: `${score.risk} (${score.level})` });
    if (score?.bot?.isBot) fields.push({ label: "Bot likelihood", value: `${score.bot.level} (${score.bot.score}/100)` });

    let verdict: ReputationSection["verdict"];
    let summary: string;
    if (statements.length > 0) {
        verdict = "malicious";
        summary = `${statements.length} Discord sanction(s) on record`;
    } else if (breachCount > 0) {
        verdict = "suspicious";
        summary = `Appears in ${breachCount} data breach(es)`;
    } else {
        verdict = "safe";
        summary = `No sanctions or breaches for ${userName}`;
    }

    return { service: "CordCat", verdict, summary, fields };
}

/** Adapter matching the shared user-reputation service signature. */
export async function analyzeUserWithCordCatReputation(userId: string, userName: string): Promise<AnalysisValue | null> {
    const section = await describeCordCat(userId, userName);
    if (section.verdict === "error") return null;

    const details: AnalysisValue["details"] = [{
        message: `[CordCat] ${section.summary}`,
        type: section.verdict === "malicious" ? "malicious" : section.verdict === "suspicious" ? "suspicious" : "safe"
    }];

    return { details, timestamp: Date.now() };
}
