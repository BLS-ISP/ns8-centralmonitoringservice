import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(__dirname, "..");

function walkFiles(dir, exts) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== "dist") {
        results.push(...walkFiles(full, exts));
      }
    } else if (exts.some((ext) => entry.name.endsWith(ext))) {
      results.push(full);
    }
  }
  return results;
}

function flattenKeys(obj, prefix = "") {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      out.push(...flattenKeys(v, key));
    } else {
      out.push(key);
    }
  }
  return out.sort();
}

test("NS8 UI Rule #1 & ARCH-12: zero createSuccessNotificationForApp and NS8 core.$root event bus", () => {
  const files = walkFiles(path.join(uiRoot, "src"), [".vue", ".js"]);
  assert.ok(files.length >= 8);
  for (const file of files) {
    const content = fs.readFileSync(file, "utf8");
    assert.ok(
      !content.includes("createSuccessNotificationForApp"),
      `Forbidden createSuccessNotificationForApp in ${file}`
    );
    assert.ok(!content.includes("v-html"), `Forbidden v-html in ${file}`);
    assert.ok(
      !content.includes("this.$root.$once("),
      `Task listeners must use (this.core && this.core.$root ? this.core.$root : this.$root).$once in ${file}`
    );
  }
});

test("NS8 UI Rule #2: Carbon icon tags in components and :icon props in data()", () => {
  const vueFiles = walkFiles(path.join(uiRoot, "src"), [".vue"]);
  for (const file of vueFiles) {
    const content = fs.readFileSync(file, "utf8");
    const tplMatch = content.match(/<template>([\s\S]*?)<\/template>/);
    const scriptMatch = content.match(/<script>([\s\S]*?)<\/script>/);
    if (!tplMatch || !scriptMatch) continue;
    const tpl = tplMatch[1];
    const script = scriptMatch[1];

    const compBlockMatch = script.match(/components\s*:\s*\{([\s\S]*?)\}/);
    const compBlock = compBlockMatch ? compBlockMatch[1] : "";

    const dataBlockMatch = script.match(/data\s*\(\)\s*\{[\s\S]*?return\s*\{([\s\S]*?)\};/);
    const dataBlock = dataBlockMatch ? dataBlockMatch[1] : "";

    const tagIcons = [...tpl.matchAll(/<([A-Z][A-Za-z0-9_]*(?:16|20|24|32))\b/g)].map((m) => m[1]);
    for (const icon of tagIcons) {
      assert.ok(
        new RegExp(`\\b${icon}\\b`).test(compBlock),
        `${path.basename(file)}: tag <${icon} /> must be registered in components`
      );
    }

    const propIcons = [...tpl.matchAll(/:icon="([A-Z][A-Za-z0-9_]*)"/g)].map((m) => m[1]);
    for (const icon of propIcons) {
      assert.ok(
        new RegExp(`\\b${icon}\\b`).test(dataBlock),
        `${path.basename(file)}: :icon="${icon}" must be exposed in data()`
      );
    }
  }
});

test("NS8 UI Rule #3: en and de translation parity and mandatory NS8 keys", () => {
  const enPath = path.join(uiRoot, "public", "i18n", "en", "translation.json");
  const dePath = path.join(uiRoot, "public", "i18n", "de", "translation.json");
  const en = JSON.parse(fs.readFileSync(enPath, "utf8"));
  const de = JSON.parse(fs.readFileSync(dePath, "utf8"));

  const enKeys = flattenKeys(en);
  const deKeys = flattenKeys(de);
  assert.deepEqual(enKeys, deKeys);

  const requiredKeys = [
    "action.list-installed-modules",
    "task.cannot_create_task",
    "error.cannot_retrieve_installed_modules",
    "error.cannot_retrieve_module_info",
  ];
  for (const rk of requiredKeys) {
    assert.ok(enKeys.includes(rk), `Missing required key ${rk}`);
  }

  // v1.0.3 NsPagination {range} placeholder verification (never {min} or {max})
  assert.equal(en.pagination.range_of_total_items, "{range} of {total} items");
  assert.equal(
    de.pagination.range_of_total_items,
    "{range} von {total} Einträgen"
  );
  const enRaw = fs.readFileSync(enPath, "utf8");
  const deRaw = fs.readFileSync(dePath, "utf8");
  assert.ok(!enRaw.includes("{min}") && !enRaw.includes("{max}"));
  assert.ok(!deRaw.includes("{min}") && !deRaw.includes("{max}"));
});

test("v1.0.3–v1.1.0 UX: simulateCustomerView, ?orgId=1, NsMultiSelect LDAP, Hub Self-Monitoring, quick links, and version 1.1.0", () => {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(uiRoot, "package.json"), "utf8")
  );
  const cfg = JSON.parse(
    fs.readFileSync(path.join(uiRoot, "public", "config.json"), "utf8")
  );
  assert.equal(pkg.version, "1.1.0");
  assert.equal(cfg.version, "1.1.0");

  const statusSrc = fs.readFileSync(
    path.join(uiRoot, "src", "views", "Status.vue"),
    "utf8"
  );
  const settingsSrc = fs.readFileSync(
    path.join(uiRoot, "src", "views", "Settings.vue"),
    "utf8"
  );
  const tenantsSrc = fs.readFileSync(
    path.join(uiRoot, "src", "views", "Tenants.vue"),
    "utf8"
  );

  assert.ok(statusSrc.includes("orgId=1"));
  assert.ok(statusSrc.includes("/d/ns8-pods-and-modules?orgId=1"));
  assert.ok(statusSrc.includes("/d/central-log-explorer?orgId=1"));
  assert.ok(settingsSrc.includes("orgId=1"));
  assert.ok(settingsSrc.includes("<NsMultiSelect"));
  assert.ok(settingsSrc.includes("ldap_admin_principals"));
  assert.ok(settingsSrc.includes("ldap_editor_principals"));
  assert.ok(settingsSrc.includes("ldap_viewer_principals"));
  assert.ok(settingsSrc.includes("discoveredLdapUsers"));
  assert.ok(settingsSrc.includes("ldapOptionScope"));
  assert.ok(settingsSrc.includes("normalizePrincipalsListWithDiscovered"));
  assert.ok(settingsSrc.includes("monitor_local_ns8_node"));
  assert.ok(settingsSrc.includes("local_node_customer"));
  assert.ok(settingsSrc.includes("local_node_site"));
  assert.ok(settingsSrc.includes("_msp_internal"));
  assert.ok(tenantsSrc.includes("simulateCustomerView"));
  assert.ok(tenantsSrc.includes("simulate_customer_view_btn"));
  assert.ok(tenantsSrc.includes("open_filtered_msp_view_btn"));
  assert.ok(tenantsSrc.includes("simulate_customer_view_modal_btn"));
  assert.ok(tenantsSrc.includes("enable_portal_now_btn"));
});
