import type { Page } from "@playwright/test";

/** Open a workspace drawer and select one of its destinations. */
export async function navigateViaWorkspace(
  page: Page,
  workspaceLabel: string,
  itemLabel: string,
): Promise<void> {
  await openWorkspace(page, workspaceLabel);
  await page
    .getByRole("group", { name: `${workspaceLabel} navigation` })
    .getByRole("link", { name: itemLabel, exact: true })
    .click();
}

/** Open a workspace drawer without selecting anything. */
export async function openWorkspace(
  page: Page,
  workspaceLabel: string,
): Promise<void> {
  await page
    .getByRole("navigation", { name: "Workspaces" })
    .getByRole("button", { name: workspaceLabel, exact: true })
    .click();
}
