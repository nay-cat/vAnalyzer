/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { PluginNative } from "@utils/types";
import { Modal, openModal, React, Toasts } from "@webpack/common";

import { safeToast } from "../../utils";
import { CordCatModal } from "./CordCatModal";
import { settings } from "../../settings";

const Native = VencordNative.pluginHelpers.vAnalyzer as PluginNative<typeof import("./native")>;

export async function analyzeUserWithCordCat(userId: string, username: string): Promise<void> {
    const apiKey = settings.store.cordCatApiKey?.trim();
    if (!apiKey) {
        safeToast("CordCat requires an API key. Set it in vAnalyzer settings.", Toasts.Type.FAILURE);
        return;
    }

    safeToast(`Querying CordCat for ${username}...`);

    const result = await Native.queryCordCat(userId, apiKey);

    if (result.status !== 200) {
        safeToast(`CordCat lookup failed: HTTP ${result.status}`, Toasts.Type.FAILURE);
        return;
    }

    const data = result.data;
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
