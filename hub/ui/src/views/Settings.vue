<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("settings.title") }}</h1>
      <div class="page-toolbar__actions">
        <NsButton
          kind="secondary"
          size="field"
          :icon="Renew20"
          :disabled="loading || saving"
          @click="getConfiguration"
        >
          {{ $t("common.refresh") }}
        </NsButton>
        <NsButton
          v-if="grafanaUrl"
          kind="ghost"
          size="field"
          :icon="Launch20"
          @click="openGrafana"
        >
          {{ $t("status.open_grafana") }}
        </NsButton>
      </div>
    </div>

    <NsInlineNotification
      v-if="feedbackBanner.title"
      :kind="feedbackBanner.kind"
      :title="feedbackBanner.title"
      :description="feedbackBanner.description"
      :showCloseButton="true"
      @close="clearFeedback"
      class="mg-bottom-md"
    />

    <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="10" />

    <cv-form v-else @submit.prevent="saveSettings">
      <!-- 1. Traefik FQDN & TLS -->
      <section class="section-card">
        <div class="section-card__header">
          <div>
            <h2 class="section-card__title">
              {{ $t("settings.ingress_section_title") }}
            </h2>
            <p class="section-card__subtitle">
              {{ $t("settings.ingress_section_desc") }}
            </p>
          </div>
        </div>

        <NsTextInput
          v-model.trim="form.host"
          :label="$t('settings.host_label')"
          :helper-text="$t('settings.host_helper')"
          placeholder="monitoring.msp.example.com"
          :disabled="saving"
          :invalid-message="validationErrors.host"
          ref="hostInput"
        />

        <div class="form-grid-2 mg-top-md">
          <NsToggle
            v-model="form.lets_encrypt"
            :label="$t('settings.lets_encrypt_label')"
            value="letsEncrypt"
            :disabled="saving"
          >
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>

          <NsToggle
            v-model="form.http2https"
            :label="$t('settings.http2https_label')"
            value="http2https"
            :disabled="saving"
          >
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>
        </div>
      </section>

      <!-- 2. Retention & Storage Mode (Local vs S3/MinIO + Thanos) -->
      <section class="section-card">
        <div class="section-card__header">
          <div>
            <h2 class="section-card__title">
              {{ $t("settings.storage_section_title") }}
            </h2>
            <p class="section-card__subtitle">
              {{ $t("settings.storage_section_desc") }}
            </p>
          </div>
        </div>

        <div class="form-grid-2">
          <NsTextInput
            v-model="form.retention_days"
            type="number"
            :label="$t('settings.retention_days_label')"
            :helper-text="$t('settings.retention_days_helper')"
            :disabled="saving"
            :invalid-message="validationErrors.retention_days"
          />

          <NsTextInput
            v-model="form.retention_size_gb"
            type="number"
            :label="$t('settings.retention_size_gb_label')"
            :helper-text="$t('settings.retention_size_gb_helper')"
            :disabled="saving"
            :invalid-message="validationErrors.retention_size_gb"
          />
        </div>

        <div class="form-grid-2">
          <NsTextInput
            v-model="form.loki_retention_days"
            type="number"
            :label="$t('settings.loki_retention_days_label')"
            :helper-text="$t('settings.loki_retention_days_helper')"
            :disabled="saving"
            :invalid-message="validationErrors.loki_retention_days"
          />

          <cv-select
            v-model="form.storage_mode"
            :label="$t('settings.storage_mode_label')"
            :disabled="saving"
          >
            <cv-select-option value="local">
              {{ $t("settings.storage_mode_local") }}
            </cv-select-option>
            <cv-select-option value="s3">
              {{ $t("settings.storage_mode_s3") }}
            </cv-select-option>
          </cv-select>
        </div>

        <!-- S3 / MinIO + Thanos Configuration -->
        <div v-if="form.storage_mode === 's3'" class="form-section-divider">
          <h3 class="form-section-title">
            {{ $t("settings.s3_section_title") }}
          </h3>
          <p class="form-section-desc">
            {{ $t("settings.s3_section_desc") }}
          </p>

          <div class="form-grid-2">
            <NsTextInput
              v-model.trim="form.s3.endpoint"
              :label="$t('settings.s3_endpoint_label')"
              :helper-text="$t('settings.s3_endpoint_helper')"
              placeholder="minio.lan:9000"
              :disabled="saving"
              :invalid-message="validationErrors.s3_endpoint"
            />

            <NsTextInput
              v-model.trim="form.s3.bucket"
              :label="$t('settings.s3_bucket_label')"
              placeholder="ns8-monitoring-tsdb"
              :disabled="saving"
              :invalid-message="validationErrors.s3_bucket"
            />
          </div>

          <div class="form-grid-2">
            <NsTextInput
              v-model.trim="form.s3.region"
              :label="$t('settings.s3_region_label')"
              placeholder="us-east-1"
              :disabled="saving"
            />

            <NsTextInput
              v-model.trim="form.s3.access_key"
              :label="$t('settings.s3_access_key_label')"
              :disabled="saving"
              :invalid-message="validationErrors.s3_access_key"
            />
          </div>

          <NsTextInput
            v-model="form.s3.secret_key"
            type="password"
            :label="$t('settings.s3_secret_key_label')"
            :placeholder="
              hasS3SecretKey ? $t('common.unchanged_placeholder') : ''
            "
            :disabled="saving"
            :invalid-message="validationErrors.s3_secret_key"
          />

          <div class="form-grid-2 mg-top-md">
            <NsToggle
              v-model="form.s3.path_style"
              :label="$t('settings.s3_path_style_label')"
              value="s3PathStyle"
              :disabled="saving"
            >
              <template slot="text-left">{{ $t("common.no") }}</template>
              <template slot="text-right">{{ $t("common.yes") }}</template>
            </NsToggle>

            <NsToggle
              v-model="form.s3.insecure"
              :label="$t('settings.s3_insecure_label')"
              value="s3Insecure"
              :disabled="saving"
            >
              <template slot="text-left">HTTPS</template>
              <template slot="text-right">HTTP</template>
            </NsToggle>
          </div>
        </div>
      </section>

      <!-- 3. NS8 LDAP / Active Directory SSO & Grafana Admin -->
      <section class="section-card">
        <div class="section-card__header">
          <div>
            <h2 class="section-card__title">
              {{ $t("settings.auth_section_title") }}
            </h2>
            <p class="section-card__subtitle">
              {{ $t("settings.auth_section_desc") }}
            </p>
          </div>
        </div>

        <NsToggle
          v-model="form.ldap_enabled"
          :label="$t('settings.ldap_enabled_label')"
          value="ldapEnabled"
          :disabled="saving"
          @change="onLdapEnabledChange"
        >
          <template slot="text-left">{{ $t("common.disabled") }}</template>
          <template slot="text-right">{{ $t("common.enabled") }}</template>
        </NsToggle>

        <div v-if="form.ldap_enabled" class="mg-top-md">
          <div class="ldap-test-row mg-bottom-md">
            <div class="ldap-test-row__input">
              <cv-select
                v-if="availableLdapDomains.length"
                v-model="form.ldap_domain"
                :label="$t('settings.ldap_domain_label')"
                :disabled="saving"
                @change="onLdapDomainChange"
              >
                <cv-select-option
                  v-for="dom in availableLdapDomains"
                  :key="dom"
                  :value="dom"
                >
                  {{ dom }}
                </cv-select-option>
              </cv-select>
              <NsTextInput
                v-else
                v-model.trim="form.ldap_domain"
                :label="$t('settings.ldap_domain_label')"
                placeholder="ad.msp.example.com"
                :disabled="saving"
                :invalid-message="validationErrors.ldap_domain"
              />
            </div>

            <NsButton
              kind="secondary"
              size="field"
              type="button"
              :icon="Renew20"
              :loading="discoveringLdapGroups"
              :disabled="saving || discoveringLdapGroups || !form.ldap_domain.trim()"
              @click="discoverLdapGroups"
            >
              {{ $t("settings.ldap_reload_groups_btn") }}
            </NsButton>
          </div>

          <p
            v-if="discoveredLdapMeta.ok && discoveredLdapGroups.length"
            class="form-section-desc"
          >
            {{
              $t("settings.ldap_discovered_summary", {
                schema: discoveredLdapMeta.schema || "ldap",
                base_dn: discoveredLdapMeta.base_dn || "-",
                count: discoveredLdapGroups.length,
              })
            }}
          </p>

          <NsInlineNotification
            v-if="discoveredLdapMeta.error"
            kind="warning"
            :title="$t('settings.ldap_discover_failed_title')"
            :description="discoveredLdapMeta.error"
            :showCloseButton="true"
            @close="discoveredLdapMeta.error = ''"
            class="mg-bottom-md"
          />

          <NsToggle
            v-if="discoveredLdapGroups.length > 0"
            v-model="manualLdapDnMode"
            :label="$t('settings.ldap_manual_dn_toggle')"
            value="manualLdapDnMode"
            :disabled="saving"
          >
            <template slot="text-left">{{ $t("common.no") }}</template>
            <template slot="text-right">{{ $t("common.yes") }}</template>
          </NsToggle>

          <!-- Dropdown Selectors when groups discovered and not in manual mode -->
          <div
            v-if="discoveredLdapGroups.length > 0 && !manualLdapDnMode"
            class="mg-top-md"
          >
            <div class="form-grid-2 mg-bottom-md">
              <cv-select
                v-model="form.ldap_admin_group"
                :label="$t('settings.ldap_admin_group_label')"
                :disabled="saving"
              >
                <cv-select-option value="">
                  {{ $t("settings.ldap_no_group_assigned") }}
                </cv-select-option>
                <cv-select-option
                  v-for="grp in ldapGroupOptionsFor(form.ldap_admin_group)"
                  :key="`admin-${grp.dn}`"
                  :value="grp.dn"
                >
                  {{ formatLdapGroupOption(grp) }}
                </cv-select-option>
              </cv-select>

              <cv-select
                v-model="form.ldap_editor_group"
                :label="$t('settings.ldap_editor_group_label')"
                :disabled="saving"
              >
                <cv-select-option value="">
                  {{ $t("settings.ldap_no_group_assigned") }}
                </cv-select-option>
                <cv-select-option
                  v-for="grp in ldapGroupOptionsFor(form.ldap_editor_group)"
                  :key="`editor-${grp.dn}`"
                  :value="grp.dn"
                >
                  {{ formatLdapGroupOption(grp) }}
                </cv-select-option>
              </cv-select>
            </div>

            <cv-select
              v-model="form.ldap_viewer_group"
              :label="$t('settings.ldap_viewer_group_label')"
              :disabled="saving"
            >
              <cv-select-option value="">
                {{ $t("settings.ldap_no_group_assigned") }}
              </cv-select-option>
              <cv-select-option
                v-for="grp in ldapGroupOptionsFor(form.ldap_viewer_group)"
                :key="`viewer-${grp.dn}`"
                :value="grp.dn"
              >
                {{ formatLdapGroupOption(grp) }}
              </cv-select-option>
            </cv-select>

            <p class="form-section-desc mg-top-md">
              {{ $t("settings.ldap_editor_group_helper") }}
            </p>
          </div>

          <!-- Manual DN / CN Inputs when no groups discovered or manual mode active -->
          <div v-else class="mg-top-md">
            <div class="form-grid-2">
              <NsTextInput
                v-model.trim="form.ldap_admin_group"
                :label="$t('settings.ldap_admin_group_label')"
                placeholder="CN=Domain Admins,CN=Users,DC=ad,DC=msp,DC=example,DC=com"
                :disabled="saving"
              />

              <NsTextInput
                v-model.trim="form.ldap_editor_group"
                :label="$t('settings.ldap_editor_group_label')"
                placeholder="CN=MSP Engineers,CN=Users,DC=ad,DC=msp,DC=example,DC=com"
                :disabled="saving"
              />
            </div>

            <NsTextInput
              v-model.trim="form.ldap_viewer_group"
              :label="$t('settings.ldap_viewer_group_label')"
              :helper-text="$t('settings.ldap_editor_group_helper')"
              placeholder="CN=MSP ReadOnly,CN=Users,DC=ad,DC=msp,DC=example,DC=com"
              :disabled="saving"
            />
          </div>

          <!-- Inline AD/LDAP User & Role Mapping Tester -->
          <div class="ldap-test-box">
            <h3 class="form-section-title">
              {{ $t("settings.ldap_test_section_title") }}
            </h3>
            <p class="form-section-desc">
              {{ $t("settings.ldap_test_section_desc") }}
            </p>

            <div class="ldap-test-row">
              <div class="ldap-test-row__input">
                <NsTextInput
                  v-model.trim="ldapTestUsername"
                  :label="$t('settings.ldap_test_username_label')"
                  :placeholder="$t('settings.ldap_test_username_placeholder')"
                  :disabled="saving || testingLdapUser"
                  :invalid-message="ldapTestValidationError"
                  @keydown.enter.prevent="runTestLdapUser"
                />
              </div>
              <NsButton
                kind="secondary"
                size="field"
                type="button"
                :icon="Search20"
                :loading="testingLdapUser"
                :disabled="saving || testingLdapUser || !form.ldap_domain.trim()"
                @click="runTestLdapUser"
              >
                {{ $t("settings.ldap_test_user_btn") }}
              </NsButton>
            </div>

            <NsInlineNotification
              v-if="ldapTestResult"
              :kind="ldapTestNotificationKind"
              :title="ldapTestNotificationTitle"
              :showCloseButton="true"
              @close="ldapTestResult = null"
              class="mg-top-md"
            >
              <template #description>
                <div>
                  <p v-if="ldapTestResult.message" class="mg-bottom-sm">
                    {{ ldapTestResult.message }}
                  </p>
                  <div v-if="ldapTestResult.found">
                    <div v-if="ldapTestResult.user_dn" class="mg-bottom-sm">
                      <strong>{{ $t("settings.ldap_test_user_dn_label") }}:</strong>
                      <span class="mono-text">{{ ldapTestResult.user_dn }}</span>
                    </div>
                    <div
                      v-if="ldapTestResult.display_name || ldapTestResult.email"
                      class="mg-bottom-sm"
                    >
                      <strong>{{ $t("settings.ldap_test_display_name_label") }}:</strong>
                      <span>
                        {{ ldapTestResult.display_name || ldapTestResult.username }}
                        <span v-if="ldapTestResult.email">
                          ({{ ldapTestResult.email }})
                        </span>
                      </span>
                    </div>
                    <div>
                      <strong>{{ $t("settings.ldap_test_groups_label") }}:</strong>
                      <span
                        v-if="
                          !ldapTestResult.member_of ||
                          !ldapTestResult.member_of.length
                        "
                      >
                        {{ $t("settings.ldap_test_no_groups") }}
                      </span>
                      <div v-else class="tag-list mg-top-md">
                        <NsTag
                          v-for="grpDn in ldapTestResult.member_of"
                          :key="grpDn"
                          kind="gray"
                          :label="grpDn"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </template>
            </NsInlineNotification>
          </div>
        </div>

        <div class="form-section-divider">
          <NsTextInput
            v-model="form.grafana_admin_password"
            type="password"
            :label="$t('settings.grafana_admin_password_label')"
            :helper-text="$t('settings.grafana_admin_password_helper')"
            :placeholder="
              hasGrafanaAdminPassword ? $t('common.unchanged_placeholder') : ''
            "
            :disabled="saving"
            :invalid-message="validationErrors.grafana_admin_password"
          />
        </div>
      </section>

      <!-- 4. NS8 Restic Backup Behavior -->
      <section class="section-card">
        <div class="section-card__header">
          <div>
            <h2 class="section-card__title">
              {{ $t("settings.backup_section_title") }}
            </h2>
            <p class="section-card__subtitle">
              {{ $t("settings.backup_section_desc") }}
            </p>
          </div>
        </div>

        <NsToggle
          v-model="form.backup_include_tsdb"
          :label="$t('settings.backup_include_tsdb_label')"
          value="backupIncludeTsdb"
          :disabled="saving"
        >
          <template slot="text-left">
            {{ $t("settings.backup_config_only") }}
          </template>
          <template slot="text-right">
            {{ $t("settings.backup_full_tsdb") }}
          </template>
        </NsToggle>
      </section>

      <NsButton
        kind="primary"
        size="field"
        :icon="Save20"
        :loading="saving"
        :disabled="saving"
        type="submit"
      >
        {{ $t("settings.save_settings_btn") }}
      </NsButton>
    </cv-form>
  </div>
</template>

<script>
import { mapState, mapActions } from "vuex";
import {
  TaskService,
  IconService,
  UtilService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import Save20 from "@carbon/icons-vue/es/save/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Launch20 from "@carbon/icons-vue/es/launch/20";
import Search20 from "@carbon/icons-vue/es/search/20";

const FQDN_RE =
  /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const S3_BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

export default {
  name: "Settings",
  mixins: [TaskService, IconService, UtilService, PageTitleService],
  pageTitle() {
    return `${this.$t("settings.title")} - ${this.appName}`;
  },
  data() {
    return {
      Save20,
      Renew20,
      Launch20,
      Search20,
      loading: false,
      saving: false,
      discoveringLdapGroups: false,
      testingLdapUser: false,
      manualLdapDnMode: false,
      discoveredLdapGroups: [],
      discoveredLdapMeta: {
        ok: false,
        schema: "",
        base_dn: "",
        error: "",
      },
      ldapTestUsername: "",
      ldapTestValidationError: "",
      ldapTestResult: null,
      hasS3SecretKey: false,
      hasGrafanaAdminPassword: false,
      availableLdapDomains: [],
      grafanaUrl: "",
      validationErrors: {},
      feedbackBanner: {
        kind: "success",
        title: "",
        description: "",
      },
      form: {
        host: "",
        lets_encrypt: false,
        http2https: true,
        retention_days: "30",
        retention_size_gb: "50",
        loki_retention_days: "30",
        backup_include_tsdb: false,
        storage_mode: "local",
        s3: {
          endpoint: "",
          bucket: "",
          region: "us-east-1",
          access_key: "",
          secret_key: "",
          insecure: false,
          path_style: true,
        },
        ldap_enabled: false,
        ldap_domain: "",
        ldap_admin_group: "Domain Admins",
        ldap_editor_group: "",
        ldap_viewer_group: "",
        grafana_admin_password: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "appName", "core"]),
    ldapTestNotificationKind() {
      if (!this.ldapTestResult) {
        return "info";
      }
      if (!this.ldapTestResult.ok || !this.ldapTestResult.found) {
        return "error";
      }
      if (this.ldapTestResult.matched_role === "None") {
        return "warning";
      }
      return "success";
    },
    ldapTestNotificationTitle() {
      if (!this.ldapTestResult) {
        return "";
      }
      if (!this.ldapTestResult.ok || !this.ldapTestResult.found) {
        return this.$t("settings.ldap_test_not_found_title");
      }
      if (this.ldapTestResult.matched_role === "None") {
        return this.$t("settings.ldap_test_unmapped_title");
      }
      return this.$t("settings.ldap_test_matched_title", {
        role: this.ldapTestResult.matched_role,
      });
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.getConfiguration();
        }
      },
    },
  },
  methods: {
    ...mapActions(["setAppConfiguredInStore", "setGrafanaUrlInStore"]),
    clearFeedback() {
      this.feedbackBanner = { kind: "success", title: "", description: "" };
    },
    openGrafana() {
      if (this.grafanaUrl) {
        window.open(this.grafanaUrl, "_blank", "noopener,noreferrer");
      }
    },
    formatLdapGroupOption(grp) {
      if (!grp) {
        return "";
      }
      if (grp.name && grp.dn && grp.name !== grp.dn) {
        return `${grp.name} — ${grp.dn}`;
      }
      return grp.dn || grp.name || "";
    },
    ldapGroupOptionsFor(currentValue) {
      const val = (currentValue || "").trim();
      if (!val) {
        return this.discoveredLdapGroups;
      }
      const exists = this.discoveredLdapGroups.some(
        (g) => g.dn === val || g.name === val
      );
      if (exists) {
        return this.discoveredLdapGroups;
      }
      return [
        { name: val, dn: val, description: "" },
        ...this.discoveredLdapGroups,
      ];
    },
    normalizeGroupSelectionWithDiscovered(rawValue) {
      const val = (rawValue || "").trim();
      if (!val || !this.discoveredLdapGroups.length) {
        return val;
      }
      const lower = val.toLowerCase();
      const byDn = this.discoveredLdapGroups.find(
        (g) => (g.dn || "").toLowerCase() === lower
      );
      if (byDn) {
        return byDn.dn;
      }
      const byName = this.discoveredLdapGroups.find(
        (g) => (g.name || "").toLowerCase() === lower
      );
      if (byName) {
        return byName.dn;
      }
      return val;
    },
    onLdapEnabledChange() {
      if (this.form.ldap_enabled) {
        if (!this.form.ldap_domain && this.availableLdapDomains.length) {
          this.form.ldap_domain = this.availableLdapDomains[0];
        }
        if (this.form.ldap_domain.trim()) {
          this.discoverLdapGroups();
        }
      }
    },
    onLdapDomainChange() {
      this.ldapTestResult = null;
      if (this.form.ldap_enabled && this.form.ldap_domain.trim()) {
        this.discoverLdapGroups();
      }
    },
    async discoverLdapGroups() {
      const domain = (this.form.ldap_domain || "").trim();
      if (!domain) {
        return;
      }
      this.discoveringLdapGroups = true;
      this.discoveredLdapMeta.error = "";
      const taskAction = "discover-ldap-groups";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.discoverLdapGroupsAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.discoverLdapGroupsCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { domain },
          extra: {
            title: this.$t("action.discover-ldap-groups"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.discoveringLdapGroups = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    discoverLdapGroupsAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.discoveringLdapGroups = false;
      this.discoveredLdapMeta = {
        ok: false,
        schema: "",
        base_dn: "",
        error: this.$t("settings.ldap_discover_failed_title"),
      };
    },
    discoverLdapGroupsCompleted(taskContext, taskResult) {
      this.discoveringLdapGroups = false;
      const out = (taskResult && taskResult.output) || {};
      this.discoveredLdapMeta = {
        ok: Boolean(out.ok),
        schema: out.schema || "",
        base_dn: out.base_dn || "",
        error: out.ok ? "" : out.error || "",
      };
      this.discoveredLdapGroups = Array.isArray(out.groups) ? out.groups : [];
      if (this.discoveredLdapGroups.length > 0) {
        this.form.ldap_admin_group = this.normalizeGroupSelectionWithDiscovered(
          this.form.ldap_admin_group
        );
        this.form.ldap_editor_group =
          this.normalizeGroupSelectionWithDiscovered(
            this.form.ldap_editor_group
          );
        this.form.ldap_viewer_group =
          this.normalizeGroupSelectionWithDiscovered(
            this.form.ldap_viewer_group
          );
      }
    },
    async runTestLdapUser() {
      this.ldapTestValidationError = "";
      const username = (this.ldapTestUsername || "").trim();
      const domain = (this.form.ldap_domain || "").trim();
      if (!username) {
        this.ldapTestValidationError = this.$t(
          "settings.ldap_test_validation_username"
        );
        return;
      }
      if (!domain) {
        this.validationErrors = Object.assign({}, this.validationErrors, {
          ldap_domain: this.$t("settings.validation_ldap_domain"),
        });
        return;
      }

      this.testingLdapUser = true;
      this.ldapTestResult = null;
      const payload = {
        domain,
        username,
        ldap_admin_group: (this.form.ldap_admin_group || "").trim(),
        ldap_editor_group: (this.form.ldap_editor_group || "").trim(),
        ldap_viewer_group: (this.form.ldap_viewer_group || "").trim(),
      };
      const taskAction = "test-ldap-user";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.testLdapUserAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.testLdapUserCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.test-ldap-user"),
            description: username,
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.testingLdapUser = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    testLdapUserAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.testingLdapUser = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("settings.ldap_test_not_found_title")
      );
    },
    testLdapUserCompleted(taskContext, taskResult) {
      this.testingLdapUser = false;
      this.ldapTestResult = (taskResult && taskResult.output) || null;
    },
    async getConfiguration() {
      this.loading = true;
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.getConfigurationAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.getConfigurationCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {},
          extra: {
            title: this.$t("action.get-configuration"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.loading = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    getConfigurationAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loading = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("settings.cannot_retrieve_configuration")
      );
    },
    getConfigurationCompleted(taskContext, taskResult) {
      this.loading = false;
      const cfg = (taskResult && taskResult.output) || {};
      this.setAppConfiguredInStore(Boolean(cfg.configured));
      this.grafanaUrl = cfg.grafana_url || "";
      this.setGrafanaUrlInStore(this.grafanaUrl);

      this.availableLdapDomains = Array.isArray(cfg.available_ldap_domains)
        ? cfg.available_ldap_domains
        : [];
      this.hasGrafanaAdminPassword = Boolean(cfg.has_grafana_admin_password);

      const s3 = cfg.s3 || {};
      this.hasS3SecretKey = Boolean(s3.has_secret_key);

      this.form = {
        host: cfg.host || "",
        lets_encrypt: Boolean(cfg.lets_encrypt),
        http2https:
          cfg.http2https !== undefined ? Boolean(cfg.http2https) : true,
        retention_days: String(cfg.retention_days || 30),
        retention_size_gb: String(
          cfg.retention_size_gb !== undefined ? cfg.retention_size_gb : 50
        ),
        loki_retention_days: String(cfg.loki_retention_days || 30),
        backup_include_tsdb: Boolean(cfg.backup_include_tsdb),
        storage_mode: cfg.storage_mode === "s3" ? "s3" : "local",
        s3: {
          endpoint: s3.endpoint || "",
          bucket: s3.bucket || "",
          region: s3.region || "us-east-1",
          access_key: s3.access_key || "",
          secret_key: "",
          insecure: Boolean(s3.insecure),
          path_style:
            s3.path_style !== undefined ? Boolean(s3.path_style) : true,
        },
        ldap_enabled: Boolean(cfg.ldap_enabled),
        ldap_domain:
          cfg.ldap_domain ||
          (this.availableLdapDomains.length
            ? this.availableLdapDomains[0]
            : ""),
        ldap_admin_group:
          cfg.ldap_admin_group !== undefined
            ? cfg.ldap_admin_group
            : "Domain Admins",
        ldap_editor_group: cfg.ldap_editor_group || "",
        ldap_viewer_group: cfg.ldap_viewer_group || "",
        grafana_admin_password: "",
      };

      if (this.form.ldap_enabled && this.form.ldap_domain.trim()) {
        this.discoverLdapGroups();
      }
    },
    validateSettingsForm() {
      const errors = {};
      const host = this.form.host.trim().toLowerCase();
      if (!FQDN_RE.test(host)) {
        errors.host = this.$t("settings.validation_host");
      }
      const retDays = parseInt(this.form.retention_days, 10);
      if (isNaN(retDays) || retDays < 1 || retDays > 3650) {
        errors.retention_days = this.$t("settings.validation_retention_days");
      }
      const retGb = parseInt(this.form.retention_size_gb, 10);
      if (isNaN(retGb) || retGb < 0 || retGb > 100000) {
        errors.retention_size_gb = this.$t(
          "settings.validation_retention_size_gb"
        );
      }
      const lokiDays = parseInt(this.form.loki_retention_days, 10);
      if (isNaN(lokiDays) || lokiDays < 1 || lokiDays > 3650) {
        errors.loki_retention_days = this.$t(
          "settings.validation_retention_days"
        );
      }

      if (this.form.storage_mode === "s3") {
        const cleanEndpoint = this.form.s3.endpoint
          .replace(/^https?:\/\//i, "")
          .trim();
        this.form.s3.endpoint = cleanEndpoint;
        if (cleanEndpoint.length < 3 || /[\/\s]/.test(cleanEndpoint)) {
          errors.s3_endpoint = this.$t("settings.validation_s3_endpoint");
        }
        if (!S3_BUCKET_RE.test(this.form.s3.bucket.trim())) {
          errors.s3_bucket = this.$t("settings.validation_s3_bucket");
        }
        if (!this.form.s3.access_key.trim()) {
          errors.s3_access_key = this.$t("settings.validation_s3_access_key");
        }
        if (!this.hasS3SecretKey && !this.form.s3.secret_key) {
          errors.s3_secret_key = this.$t("settings.validation_s3_secret_key");
        }
      }

      if (this.form.ldap_enabled && !this.form.ldap_domain.trim()) {
        errors.ldap_domain = this.$t("settings.validation_ldap_domain");
      }

      if (
        this.form.grafana_admin_password.length > 0 &&
        this.form.grafana_admin_password.length < 8
      ) {
        errors.grafana_admin_password = this.$t(
          "settings.validation_grafana_password"
        );
      }

      this.validationErrors = errors;
      return Object.keys(errors).length === 0;
    },
    buildConfigurePayload() {
      const secretKeyUnchanged = Boolean(
        this.hasS3SecretKey && !this.form.s3.secret_key
      );
      return {
        host: this.form.host.trim().toLowerCase(),
        lets_encrypt: Boolean(this.form.lets_encrypt),
        http2https: Boolean(this.form.http2https),
        retention_days: parseInt(this.form.retention_days, 10),
        retention_size_gb: parseInt(this.form.retention_size_gb, 10),
        loki_retention_days: parseInt(this.form.loki_retention_days, 10),
        backup_include_tsdb: Boolean(this.form.backup_include_tsdb),
        storage_mode: this.form.storage_mode === "s3" ? "s3" : "local",
        s3: {
          endpoint: this.form.s3.endpoint.trim(),
          bucket: this.form.s3.bucket.trim(),
          region: this.form.s3.region.trim() || "us-east-1",
          access_key: this.form.s3.access_key.trim(),
          secret_key: this.form.s3.secret_key || "",
          secret_key_unchanged: secretKeyUnchanged,
          insecure: Boolean(this.form.s3.insecure),
          path_style: Boolean(this.form.s3.path_style),
        },
        ldap_enabled: Boolean(this.form.ldap_enabled),
        ldap_domain: this.form.ldap_domain.trim(),
        ldap_admin_group: this.form.ldap_admin_group.trim(),
        ldap_editor_group: this.form.ldap_editor_group.trim(),
        ldap_viewer_group: this.form.ldap_viewer_group.trim(),
        grafana_admin_password: this.form.grafana_admin_password || "",
      };
    },
    async saveSettings() {
      if (!this.validateSettingsForm()) {
        return;
      }
      this.saving = true;
      this.validationErrors = {};
      const payload = this.buildConfigurePayload();
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.saveSettingsAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.saveSettingsValidationFailed
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.saveSettingsCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("settings.configure_instance", {
              instance: this.instanceName,
            }),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.saving = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    saveSettingsAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.saving = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("settings.save_failed")
      );
    },
    saveSettingsValidationFailed(validationErrors) {
      this.saving = false;
      const mapped = {};
      const errList = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];
      errList.forEach((item) => {
        let key = item.field || item.parameter || "host";
        if (key.startsWith("s3.")) {
          key = key.replace("s3.", "s3_");
        }
        mapped[key] = this.$te(`validation.${item.error}`)
          ? this.$t(`validation.${item.error}`)
          : item.error;
      });
      this.validationErrors = mapped;
    },
    saveSettingsCompleted(taskContext, taskResult) {
      this.saving = false;
      const out = (taskResult && taskResult.output) || {};
      this.setAppConfiguredInStore(true);
      if (out.grafana_url) {
        this.grafanaUrl = out.grafana_url;
        this.setGrafanaUrlInStore(out.grafana_url);
      }
      this.feedbackBanner = {
        kind: "success",
        title: this.$t("settings.saved_title"),
        description: this.$t("settings.saved_description"),
      };
      this.getConfiguration();
    },
  },
};
</script>
