# Spec: `hub-ui` — NethServer 8 Cockpit Management UI for `central-monitoring-hub`

- **Module ID:** `hub-ui`
- **Depends on:** `hub-core`, `hub-tenancy-gateway`, `hub-probes-alerting`
- **Consumed by:** MSP Administrators inside NS8 Cluster-Admin (Cockpit)

---

## Assumptions

1. `hub/ui/` follows the standard NethServer 8 application UI architecture: Vue 2.7 + Carbon Design System (`@carbon/vue`, `@carbon/icons-vue`) + `@nethserver/ns8-ui-lib` + `vue-i18n`, communicating exclusively with NS8 backend actions via `TaskService` (`createModuleTaskForApp` / `createClusterTaskForApp`).
2. On the local Windows build host (`Node.js v26.13.1`, `npm 11.20.0`), OpenSSL 3 is active by default; if `@vue/cli-service` v4 (webpack 4) is used, `package.json` scripts include cross-platform OpenSSL compatibility or `@vue/cli-service` v5 (`^5.0.8`) so `npm run build` and `npm run test:unit` succeed natively on Node 26 without environment tweaks! (Using `@vue/cli-service ^5.0.8` is preferred so webpack 5 works natively on Node 18–26 without `--openssl-legacy-provider`).
3. Both **English (`en`)** and **German (`de`)** translations (`ui/public/i18n/en/translation.json` and `ui/public/i18n/de/translation.json`) are first-class and complete, matching the bilingual MSP team workflow.

---

## Objective

Deliver a clean, responsive, accessible NethServer 8 Cockpit administration UI (`hub/ui/`) for `central-monitoring-hub` enabling MSP engineers to:
1. **Status & Overview (`Status.vue`):** View core NS8 container/node status (via built-in `get-status`) alongside Hub operational health, storage usage (`local` vs `s3` Thanos/Loki), active series/tenants/targets/firing alerts counts, and a 1-click **"Open Grafana"** launch button (via `get-overview`).
2. **Tenants, Multi-User Customer Portals & Onboarding (`Tenants.vue`):** Create/edit/delete customer tenants and sites, toggle strictly isolated Customer Grafana Portals (`customer_portal_enabled`), manage **multiple Grafana accounts per customer** (`list-portal-users`, `save-portal-user`, `delete-portal-user` with `Viewer`/`Editor` role, disable switch, password reset, and direct Grafana Org login link), copy newly generated tokens once, rotate tokens with grace periods (`rotate-token`), and generate/download 1-click **Standalone Grafana Alloy** onboarding bundles for **Linux**, **Windows**, and **Docker** (`generate-agent-bundle`).
3. **Central Targets & Probes (`Targets.vue`):** Manage central `ns8-federation`, `exporter`, `blackbox` (HTTP/HTTPS/SSL, DNS, TCP), and `snmp` (v2c/v3) scrape targets with customer/site dropdowns.
4. **Alerting & Maintenance Windows (`Alerting.vue`):** Configure NS8 Smarthost / SMTP email, PSA/Ticket Webhook, MS Teams / Slack, Ntfy / Telegram / Gotify push notifications, per-customer email routing, toggle standard MSP rule packs, fire live test alerts (`test-alert`), and create/expire Alertmanager maintenance windows (`list-silences`, `create-silence`, `delete-silence`).
5. **Settings & Live AD/LDAP Discovery (`Settings.vue`):** Configure FQDN (`host`), Let's Encrypt, HTTP->HTTPS, Prometheus/Loki retention, Restic TSDB backup toggle (`backup_include_tsdb`), Storage Mode (`local` vs `s3`/MinIO credentials), **NS8 LDAP/AD SSO** (`ldap_enabled`, domain picker, live `discover-ldap-groups` group browser populating `ldap_admin_group`, `ldap_editor_group`, and `ldap_viewer_group`, plus interactive `test-ldap-user` role-mapping verifier), and Grafana admin password (`configure-module`).

---

## Tech Stack

- **Frontend Framework:** Vue `^2.7.16`, Vue Router `^3.6.5`, Vuex `^3.6.2`, VueI18n `^8.28.2`.
- **NS8 & Design System:** `@nethserver/ns8-ui-lib` (`^1.10.0`), `@carbon/vue` (`^2.37.0`), `@carbon/icons-vue` (`^10.28.0`), Carbon Styles.
- **Build & Test Tooling:** `@vue/cli-service` (`^5.0.8` — native Node 26 / OpenSSL 3 support), Vitest or Jest / Node test runner for unit & static NS8 UI rule verification.
- **Detected Local Host Runtimes (Windows):**
  - `node --version`: `v26.13.1`
  - `npm --version`: `11.20.0`
  - `python --version`: `Python 3.14.10`

---

## Commands

```powershell
# Install Hub UI dependencies (inside hub/ui/)
npm --prefix hub/ui install

# Build production Cockpit UI bundle to hub/ui/dist/
npm --prefix hub/ui run build

# Run UI lint & automated NS8 UI rule / i18n parity checks
npm --prefix hub/ui test
python -m pytest tests/hub_ui -v
```

---

## Project Structure

```text
hub/
  ui/
    package.json                       -> Vue 2.7, @vue/cli-service ^5, @nethserver/ns8-ui-lib, @carbon/vue, @carbon/icons-vue
    vue.config.js                      -> Relative publicPath: "./" for NS8 Cockpit sub-path hosting
    public/
      index.html
      config.json                      -> NS8 Cockpit app descriptor
      metadata.json                    -> NS8 Software Center catalog descriptor (name, en/de description, categories, docs, GHCR source)
      module_default_icon.png          -> NS8 Software Center PNG application icon (packaged into /ui/ inside module scratch image)
      i18n/
        en/translation.json            -> Complete English strings + mandatory NS8 core keys
        de/translation.json            -> Complete German strings + mandatory NS8 core keys
    src/
      main.js                          -> Loads BOTH en and de locales into VueI18n with fallbackLocale: "en"
      App.vue                          -> Carbon shell, side nav (Status, Tenants, Targets, Alerting, Settings), error handling
      router/index.js                  -> Hash router routes (/status, /tenants, /targets, /alerting, /settings)
      store/index.js                   -> Vuex module state
      views/
        Status.vue                     -> Calls core get-status + custom get-overview (NEVER overrides core get-status!)
        Tenants.vue                    -> Tenant CRUD modal, one-time token banner, rotate-token modal, Alloy Onboarding Drawer
        Targets.vue                    -> Central targets DataTable + type-specific modal (Federation, Exporter, Blackbox, SNMP v2c/v3 incl. qnap & printer)
        Alerting.vue                   -> Tabs: Notification Channels & Rule Packs | Maintenance Windows (Silences) + Test Alert button
        Settings.vue                   -> FQDN/TLS, Retention, Local vs S3/Thanos form, NS8 LDAP SSO, Backup TSDB switch, Admin password
        About.vue                      -> Module metadata & documentation links
scripts/
  generate-repomd.py                   -> Generates NethServer 8 Software Center repository metadata (repodata/repomd.json + icons) for GitHub Pages 1-click installation
tests/
  hub_ui/                              -> Automated static & schema alignment checks (icons, TaskService calls, metadata.json, i18n parity)
```

---

## Mandatory NS8 Cockpit UI Rules (Strictly Enforced)

### 1. Notification API Signatures in `TaskService` (NS8 UI Rule #1)
- `this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"))` takes **2 arguments**.
- `this.createNotificationForApp(notification)` takes **1 notification object**.
- **NEVER call `this.createSuccessNotificationForApp(...)`!** That method does **not** exist in `@nethserver/ns8-ui-lib` and throws a runtime `TypeError`!
- For task completion feedback, omit `isNotificationHidden: true` in `extra` on mutating tasks (so NS8's built-in task toast appears automatically) and/or render `<NsInlineNotification kind="success" ... />` in the view (especially for displaying newly generated/rotated bearer tokens with a Copy button!).

### 2. Carbon Icons Registration (NS8 UI Rule #2)
- Every `@carbon/icons-vue` icon rendered as a tag in `<template>` (e.g., `<Launch20 />`, `<Add20 />`, `<Copy20 />`, `<Renew20 />`) **MUST** be registered in `components: { Launch20, Add20, ... }`.
- Every icon passed as a component prop (e.g., `:icon="Save20"` on `<NsButton>`) **MUST** be returned from `data() { return { Save20, ... }; }`.

### 3. `VueI18n` Initialization & Required Keys (NS8 UI Rule #3)
- `hub/ui/src/main.js` **MUST** load `en` eagerly alongside the active user locale (`messages: { en: enMessages, de: deMessages }`, `fallbackLocale: "en"`).
- Both `public/i18n/en/translation.json` and `public/i18n/de/translation.json` **MUST** contain:
  - `action.list-installed-modules`
  - `task.cannot_create_task`
  - `error.cannot_retrieve_installed_modules`
  - `error.cannot_retrieve_module_info`
  plus identical key trees across `en` and `de`!

---

## Code Style

### Compliant `TaskService` Invocation & Icon Registration in Vue 2 (`Settings.vue` / `Tenants.vue`)

```javascript
import { TaskService, IconService, UtilService } from "@nethserver/ns8-ui-lib";
import Save20 from "@carbon/icons-vue/es/save/20";
import Launch20 from "@carbon/icons-vue/es/launch/20";

export default {
  name: "Settings",
  components: {
    Launch20, // Used as <Launch20 /> in <template>
  },
  mixins: [TaskService, IconService, UtilService],
  data() {
    return {
      Save20, // Passed as :icon="Save20" prop to <NsButton>
      loading: false,
      saving: false,
      validationErrors: {},
    };
  },
  methods: {
    async saveSettings(payload) {
      this.saving = true;
      this.validationErrors = {};
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      const eventBus = this.core && this.core.$root ? this.core.$root : this.$root;
      eventBus.$once(`${taskAction}-aborted-${eventId}`, this.onSaveAborted);
      eventBus.$once(`${taskAction}-validation-failed-${eventId}`, this.onValidationFailed);
      eventBus.$once(`${taskAction}-completed-${eventId}`, this.onSaveCompleted);

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("settings.configure_instance", { instance: this.instanceName }),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.saving = false;
      }
    },
  },
};
```

---

## Testing Strategy

- **Build Verification:** `npm --prefix hub/ui run build` must complete with exit code `0` and emit `hub/ui/dist/index.html` + hashed JS/CSS chunks without missing imports.
- **Automated NS8 UI Audit (`tests/hub_ui/test_ui_compliance.py` + `npm test`):**
  - AST/Regex scan across `hub/ui/src/**/*.vue` and `*.js` asserting:
    1. Zero occurrences of `createSuccessNotificationForApp`.
    2. Every `createErrorNotificationForApp(` call passes 2 arguments.
    3. Every `<*16 />`, `<*20 />`, `<*24 />`, `<*32 />` Carbon icon tag in `<template>` is imported and listed in `components: { ... }`, and every `:icon="..."` identifier is exposed in `data()`.
    4. Every NS8 task payload shape matches the required properties in `shared/schemas/hub-*-input.json`.
    5. `en/translation.json` and `de/translation.json` both parse cleanly, contain all 4 mandatory NS8 core keys, and have 100% matching key sets.

---

## Boundaries

- **Always:**
  - Treat secret fields (`s3.secret_key`, `smtp_password`, `portal_viewer_password`, `snmp_community`, tokens) as write-only in edit forms, sending `*_unchanged: true` when left untouched by the admin.
  - Display newly minted or rotated bearer tokens in a dismissible one-time warning modal/banner with a Copy button, clearly stating the secret will not be shown again.
  - Map NS8 backend `validation-failed` error arrays (`field`, `error`) directly onto Carbon `<NsTextInput invalid-message="...">` fields.
- **Ask first:**
  - Adding heavy third-party chart libraries (Grafana already provides rich charts; Cockpit UI stays fast and lightweight).
- **Never:**
  - Call `this.createSuccessNotificationForApp(...)`.
  - Render user-provided strings with `v-html` (XSS prevention).
  - Hardcode English or German text in `.vue` templates instead of `$t(...)`.

---

## Success Criteria

- [ ] `npm --prefix hub/ui run build` succeeds cleanly on `Node.js v26.13.1` / `npm 11.20.0`, producing `hub/ui/dist/`.
- [ ] All 5 primary views (`Status`, `Tenants`, `Targets`, `Alerting`, `Settings`) cover 100% of Hub NS8 actions defined in `shared/schemas/hub-*.json`.
- [ ] Automated UI audit suite passes all 3 NS8 Cockpit UI rules (`TaskService` notifications, Carbon icon registration, `en`+`de` `VueI18n` parity & mandatory keys).
