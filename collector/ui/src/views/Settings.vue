<template>
  <div class="bx--grid bx--grid--full-width bx--no-gutter">
    <div class="collector-page-header">
      <div>
        <h1 class="collector-page-title">{{ $t("settings.title") }}</h1>
        <p class="collector-page-subtitle">{{ $t("settings.subtitle") }}</p>
      </div>
    </div>

    <div v-if="saveBannerVisible" class="collector-section-gap">
      <NsInlineNotification
        kind="success"
        :title="$t('settings.saved_title')"
        :description="$t('settings.saved_description')"
        :showCloseButton="true"
        @close="saveBannerVisible = false"
      />
    </div>

    <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="8" />

    <cv-form v-else @submit.prevent="saveSettings">
      <section class="collector-card collector-section-gap" aria-labelledby="hub-conn-heading">
        <h2 id="hub-conn-heading" class="collector-card-title">
          {{ $t("settings.hub_section_title") }}
        </h2>
        <p class="section-helper">{{ $t("settings.hub_section_desc") }}</p>

        <div class="settings-grid-2col">
          <NsTextInput
            v-model.trim="form.hub_url"
            :label="$t('settings.hub_url')"
            :placeholder="$t('settings.hub_url_placeholder')"
            :helper-text="$t('settings.hub_url_helper')"
            :invalid-message="validationErrors.hub_url"
            required
          />

          <NsPasswordInput
            v-model="form.auth_token"
            :label="$t('settings.auth_token')"
            :placeholder="$t('settings.auth_token_placeholder')"
            :helper-text="
              hasStoredToken
                ? $t('settings.auth_token_keep_helper', { prefix: storedTokenPrefix })
                : ''
            "
            :invalid-message="validationErrors.auth_token"
          />
        </div>

        <div class="field-spacing">
          <cv-checkbox
            v-model="form.tls_skip_verify"
            value="hub_tls_skip_verify"
            :label="$t('settings.tls_skip_verify')"
          />
          <p class="checkbox-helper">{{ $t("settings.tls_skip_verify_helper") }}</p>
        </div>

        <div class="probe-toolbar">
          <NsButton
            type="button"
            kind="secondary"
            size="field"
            :icon="Plug20"
            :disabled="testingConnection || saving"
            @click="testHubConnection"
          >
            {{
              testingConnection
                ? $t("settings.testing_connection")
                : $t("settings.test_connection")
            }}
          </NsButton>
        </div>

        <div v-if="probeResult" class="field-spacing">
          <NsInlineNotification
            :kind="probeResult.ok ? 'success' : 'error'"
            :title="
              probeResult.ok
                ? $t('settings.probe_ok_title')
                : $t('settings.probe_failed_title')
            "
            :description="formatProbeSummary(probeResult)"
            :showCloseButton="true"
            @close="probeResult = null"
          />
        </div>
      </section>

      <section class="collector-card collector-section-gap" aria-labelledby="identity-heading">
        <h2 id="identity-heading" class="collector-card-title">
          {{ $t("settings.identity_section_title") }}
        </h2>
        <p class="section-helper">{{ $t("settings.identity_section_desc") }}</p>

        <div class="settings-grid-3col">
          <NsTextInput
            v-model.trim="form.customer"
            :label="$t('settings.customer')"
            :placeholder="$t('settings.customer_placeholder')"
            :helper-text="$t('settings.customer_helper')"
            :invalid-message="validationErrors.customer"
            required
          />

          <NsTextInput
            v-model.trim="form.site"
            :label="$t('settings.site')"
            :placeholder="$t('settings.site_placeholder')"
            :helper-text="$t('settings.site_helper')"
            :invalid-message="validationErrors.site"
            required
          />

          <NsTextInput
            v-model.trim="form.collector_id"
            :label="$t('settings.collector_id')"
            :placeholder="$t('settings.collector_id_placeholder')"
            :helper-text="$t('settings.collector_id_helper')"
            :invalid-message="validationErrors.collector_id"
          />
        </div>
      </section>

      <section class="collector-card collector-section-gap" aria-labelledby="telemetry-heading">
        <h2 id="telemetry-heading" class="collector-card-title">
          {{ $t("settings.telemetry_section_title") }}
        </h2>
        <p class="section-helper">{{ $t("settings.telemetry_section_desc") }}</p>

        <div class="field-spacing">
          <cv-checkbox
            v-model="form.collect_local_ns8"
            value="collect_local_ns8"
            :label="$t('settings.collect_local_ns8')"
          />
          <p class="checkbox-helper">{{ $t("settings.collect_local_ns8_helper") }}</p>
        </div>

        <div class="field-spacing">
          <cv-checkbox
            v-model="form.enable_syslog_receiver"
            value="enable_syslog_receiver"
            :label="$t('settings.enable_syslog_receiver')"
          />
          <p class="checkbox-helper">{{ $t("settings.enable_syslog_receiver_helper") }}</p>
        </div>

        <div v-if="form.enable_syslog_receiver" class="field-spacing narrow-input">
          <NsTextInput
            v-model.number="form.syslog_port"
            type="number"
            :label="$t('settings.syslog_port')"
            :helper-text="$t('settings.syslog_port_helper')"
            :invalid-message="validationErrors.syslog_port"
          />
        </div>
      </section>

      <section class="collector-card collector-section-gap" aria-labelledby="wal-heading">
        <h2 id="wal-heading" class="collector-card-title">
          {{ $t("settings.wal_section_title") }}
        </h2>
        <p class="section-helper">{{ $t("settings.wal_section_desc") }}</p>

        <div class="narrow-input">
          <NsTextInput
            v-model.number="form.wal_max_disk_mb"
            type="number"
            :label="$t('settings.wal_max_disk_mb')"
            :helper-text="$t('settings.wal_max_disk_mb_helper')"
            :invalid-message="validationErrors.wal_max_disk_mb"
          />
        </div>
      </section>

      <div class="submit-footer">
        <NsButton
          type="submit"
          kind="primary"
          size="field"
          :icon="Save20"
          :disabled="saving"
        >
          {{ $t("settings.save_settings") }}
        </NsButton>
      </div>
    </cv-form>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { TaskService, IconService, UtilService } from "@nethserver/ns8-ui-lib";
import Save20 from "@carbon/icons-vue/es/save/20";
import Plug20 from "@carbon/icons-vue/es/plug/20";

const CUSTOMER_RE = /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/;
const SITE_RE = /^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/;
const HTTPS_URL_RE = /^https:\/\/[^/\s]+(\/.*)?$/;

export default {
  name: "Settings",
  components: {},
  mixins: [TaskService, IconService, UtilService],
  data() {
    return {
      Save20,
      Plug20,
      loading: false,
      saving: false,
      testingConnection: false,
      saveBannerVisible: false,
      hasStoredToken: false,
      storedTokenPrefix: "",
      probeResult: null,
      validationErrors: {},
      form: {
        hub_url: "",
        auth_token: "",
        customer: "",
        site: "",
        collector_id: "",
        collect_local_ns8: true,
        enable_syslog_receiver: false,
        syslog_port: 5514,
        wal_max_disk_mb: 2048,
        tls_skip_verify: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core"]),
  },
  created() {
    this.loadConfiguration();
  },
  methods: {
    async loadConfiguration() {
      if (!this.instanceName) return;
      this.loading = true;
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.loading = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (taskContext, taskResult) => {
          const output = (taskResult && taskResult.output) || (taskContext && taskContext.output);
          if (output) {
            this.hasStoredToken = Boolean(output.has_auth_token);
            this.storedTokenPrefix = output.auth_token_prefix || "";
            this.form = {
              hub_url: output.hub_url || "",
              auth_token: "",
              customer: output.customer || "",
              site: output.site || "",
              collector_id: output.collector_id || "",
              collect_local_ns8: Boolean(output.collect_local_ns8),
              enable_syslog_receiver: Boolean(output.enable_syslog_receiver),
              syslog_port: Number(output.syslog_port) || 5514,
              wal_max_disk_mb: Number(output.wal_max_disk_mb) || 2048,
              tls_skip_verify: Boolean(output.tls_skip_verify),
            };
          }
          this.loading = false;
        }
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
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.loading = false;
      }
    },
    validateClientForm() {
      const errs = {};
      if (!HTTPS_URL_RE.test(this.form.hub_url || "")) {
        errs.hub_url = this.$t("settings.validation_invalid_hub_url");
      }
      if (!this.hasStoredToken && !this.form.auth_token) {
        errs.auth_token = this.$t("settings.validation_auth_token_required");
      } else if (this.form.auth_token && this.form.auth_token.length < 16) {
        errs.auth_token = this.$t("settings.validation_auth_token_too_short");
      }
      if (!CUSTOMER_RE.test(this.form.customer || "")) {
        errs.customer = this.$t("settings.validation_invalid_customer");
      }
      if (!SITE_RE.test(this.form.site || "")) {
        errs.site = this.$t("settings.validation_invalid_site");
      }
      this.validationErrors = errs;
      return Object.keys(errs).length === 0;
    },
    async testHubConnection() {
      this.validationErrors = {};
      if (!HTTPS_URL_RE.test(this.form.hub_url || "")) {
        this.validationErrors = {
          hub_url: this.$t("settings.validation_invalid_hub_url"),
        };
        return;
      }

      this.testingConnection = true;
      this.probeResult = null;
      const taskAction = "test-hub-connection";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.testingConnection = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (taskContext, taskResult) => {
          const output = (taskResult && taskResult.output) || (taskContext && taskContext.output);
          if (output) {
            this.probeResult = output;
          }
          this.testingConnection = false;
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            hub_url: this.form.hub_url,
            auth_token: this.form.auth_token || "",
            tls_skip_verify: Boolean(this.form.tls_skip_verify),
          },
          extra: {
            title: this.$t("action.test-hub-connection"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.testingConnection = false;
      }
    },
    formatProbeSummary(probe) {
      const parts = [probe.message || ""];
      if (probe.verified_customer) {
        parts.push(
          this.$t("settings.probe_verified_customer", {
            customer: probe.verified_customer,
          })
        );
      }
      if (probe.http_status > 0) {
        parts.push(this.$t("settings.probe_http_status", { code: probe.http_status }));
      }
      if (typeof probe.latency_ms === "number") {
        parts.push(this.$t("settings.probe_latency", { ms: probe.latency_ms }));
      }
      return parts.filter(Boolean).join(" — ");
    },
    async saveSettings() {
      this.saveBannerVisible = false;
      if (!this.validateClientForm()) {
        return;
      }

      this.saving = true;
      const tokenUnchanged = Boolean(this.hasStoredToken && !this.form.auth_token);
      const payload = {
        hub_url: this.form.hub_url,
        auth_token: tokenUnchanged ? "" : this.form.auth_token,
        auth_token_unchanged: tokenUnchanged,
        customer: this.form.customer,
        site: this.form.site,
        collector_id: this.form.collector_id || "",
        collect_local_ns8: Boolean(this.form.collect_local_ns8),
        enable_syslog_receiver: Boolean(this.form.enable_syslog_receiver),
        syslog_port: Number(this.form.syslog_port) || 5514,
        wal_max_disk_mb: Number(this.form.wal_max_disk_mb) || 2048,
        tls_skip_verify: Boolean(this.form.tls_skip_verify),
      };

      const taskAction = "configure-module";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.saving = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        (validationErrors, taskContext) => {
          this.saving = false;
          const errs = Array.isArray(validationErrors)
            ? validationErrors
            : (validationErrors && validationErrors.output) ||
              (taskContext && taskContext.output) ||
              [];
          const mapped = {};
          if (Array.isArray(errs)) {
            errs.forEach((e) => {
              if (e && e.field) mapped[e.field] = e.error || this.$t("error.validation_failed");
            });
          }
          this.validationErrors = mapped;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        () => {
          this.saving = false;
          this.saveBannerVisible = true;
          this.loadConfiguration();
        }
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
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.saving = false;
      }
    },
  },
};
</script>

