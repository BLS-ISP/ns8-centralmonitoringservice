<template>
  <div class="bx--grid bx--grid--full-width bx--no-gutter">
    <div class="collector-page-header">
      <div>
        <h1 class="collector-page-title">{{ $t("status.title") }}</h1>
      </div>
      <NsButton
        kind="tertiary"
        size="field"
        :icon="Renew20"
        :disabled="loadingStatus || loadingConfig"
        @click="refreshAll"
      >
        {{ $t("common.refresh") }}
      </NsButton>
    </div>

    <div v-if="!loadingConfig && !config.configured" class="collector-section-gap">
      <NsInlineNotification
        kind="warning"
        :title="$t('status.unconfigured_title')"
        :description="$t('status.unconfigured_description')"
        :showCloseButton="false"
      />
      <div style="margin-top: 0.75rem">
        <NsButton kind="primary" :icon="Settings20" @click="$router.push('/settings')">
          {{ $t("status.go_to_settings") }}
        </NsButton>
      </div>
    </div>

    <div class="bx--row collector-section-gap">
      <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4" style="margin-bottom: 1rem">
        <section class="collector-card" aria-labelledby="identity-card-heading">
          <h2 id="identity-card-heading" class="collector-card-title">
            {{ $t("status.identity_card_title") }}
          </h2>
          <cv-skeleton-text v-if="loadingConfig" :paragraph="true" :line-count="5" />
          <div v-else class="collector-kv-list">
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.customer") }}</span>
              <span class="collector-kv-value">{{ config.customer || "—" }}</span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.site") }}</span>
              <span class="collector-kv-value">{{ config.site || "—" }}</span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.collector_id") }}</span>
              <span class="collector-kv-value">
                <code>{{ config.collector_id || "—" }}</code>
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.hub_url") }}</span>
              <span class="collector-kv-value">{{ config.hub_url || "—" }}</span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.auth_token_status") }}</span>
              <span class="collector-kv-value">
                <cv-tag
                  v-if="config.has_auth_token"
                  kind="green"
                  :label="$t('status.token_present', { prefix: config.auth_token_prefix })"
                />
                <cv-tag v-else kind="gray" :label="$t('status.token_missing')" />
              </span>
            </div>
          </div>
        </section>
      </div>

      <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4" style="margin-bottom: 1rem">
        <section class="collector-card" aria-labelledby="runtime-card-heading">
          <h2 id="runtime-card-heading" class="collector-card-title">
            {{ $t("status.runtime_card_title") }}
          </h2>
          <cv-skeleton-text v-if="loadingConfig" :paragraph="true" :line-count="5" />
          <div v-else class="collector-kv-list">
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.alloy_agent") }}</span>
              <span class="collector-kv-value">
                <cv-tag
                  :kind="healthBadgeKind(config.health.alloy_status)"
                  :label="healthStatusLabel(config.health.alloy_status)"
                />
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.pve_sidecar") }}</span>
              <span class="collector-kv-value">
                <cv-tag
                  :kind="healthBadgeKind(config.health.pve_exporter_status)"
                  :label="healthStatusLabel(config.health.pve_exporter_status)"
                />
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.wal_buffer_usage") }}</span>
              <span class="collector-kv-value">
                {{ formatBytes(config.health.wal_usage_bytes) }}
                <small style="display: block; color: #525252">
                  {{ $t("status.wal_cap_label", { cap: config.wal_max_disk_mb }) }}
                </small>
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.local_ns8_telemetry") }}</span>
              <span class="collector-kv-value">
                <cv-tag
                  :kind="config.collect_local_ns8 ? 'green' : 'gray'"
                  :label="config.collect_local_ns8 ? $t('common.enabled') : $t('common.disabled')"
                />
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.syslog_receiver") }}</span>
              <span class="collector-kv-value">
                <cv-tag
                  :kind="config.enable_syslog_receiver ? 'blue' : 'gray'"
                  :label="
                    config.enable_syslog_receiver
                      ? 'UDP/TCP :' + config.syslog_port
                      : $t('common.disabled')
                  "
                />
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("status.lan_targets_total") }}</span>
              <span class="collector-kv-value">{{ config.health.local_targets_count }}</span>
            </div>
          </div>
        </section>
      </div>
    </div>

    <div class="bx--row">
      <div class="bx--col-lg-16 bx--col-md-8 bx--col-sm-4">
        <section class="collector-card" aria-labelledby="core-status-heading">
          <h2 id="core-status-heading" class="collector-card-title">
            {{ $t("status.core_module_card_title") }}
          </h2>
          <cv-skeleton-text v-if="loadingStatus" :paragraph="true" :line-count="4" />
          <div v-else class="bx--row">
            <div class="bx--col-lg-4 bx--col-md-4 bx--col-sm-4" style="margin-bottom: 1rem">
              <h3 class="status-sub-heading">{{ $t("status.installation_node") }}</h3>
              <p>
                {{
                  coreStatus.node
                    ? $t("status.node_label", { node: coreStatus.node })
                    : "—"
                }}
              </p>
            </div>

            <div class="bx--col-lg-6 bx--col-md-4 bx--col-sm-4" style="margin-bottom: 1rem">
              <h3 class="status-sub-heading">{{ $t("status.services") }}</h3>
              <p v-if="!coreStatus.services || coreStatus.services.length === 0" class="muted-note">
                {{ $t("status.no_services") }}
              </p>
              <ul v-else class="clean-status-list">
                <li v-for="svc in coreStatus.services" :key="svc.name" class="clean-status-item">
                  <CheckmarkFilled20 v-if="svc.active && !svc.failed" class="icon-ok" />
                  <WarningAlt20 v-else class="icon-warn" />
                  <span>{{ svc.name }}</span>
                  <cv-tag
                    :kind="svc.failed ? 'red' : svc.active ? 'green' : 'gray'"
                    :label="
                      svc.failed
                        ? $t('status.service_failed')
                        : svc.active
                        ? $t('status.service_active')
                        : $t('status.service_inactive')
                    "
                  />
                </li>
              </ul>
            </div>

            <div class="bx--col-lg-6 bx--col-md-8 bx--col-sm-4" style="margin-bottom: 1rem">
              <h3 class="status-sub-heading">{{ $t("status.images") }}</h3>
              <p v-if="!coreStatus.images || coreStatus.images.length === 0" class="muted-note">
                {{ $t("status.no_images") }}
              </p>
              <ul v-else class="clean-status-list">
                <li v-for="img in coreStatus.images" :key="img.name" class="clean-status-item">
                  <code>{{ img.name }}</code>
                  <span>{{ formatBytes(img.size) }}</span>
                </li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { TaskService, IconService, UtilService } from "@nethserver/ns8-ui-lib";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Settings20 from "@carbon/icons-vue/es/settings/20";
import CheckmarkFilled20 from "@carbon/icons-vue/es/checkmark--filled/20";
import WarningAlt20 from "@carbon/icons-vue/es/warning--alt/20";

export default {
  name: "Status",
  components: {
    CheckmarkFilled20,
    WarningAlt20,
  },
  mixins: [TaskService, IconService, UtilService],
  data() {
    return {
      Renew20,
      Settings20,
      loadingStatus: false,
      loadingConfig: false,
      coreStatus: {
        node: null,
        services: [],
        images: [],
        volumes: [],
      },
      config: {
        configured: false,
        hub_url: "",
        has_auth_token: false,
        auth_token_prefix: "",
        customer: "",
        site: "",
        collector_id: "",
        collect_local_ns8: true,
        enable_syslog_receiver: false,
        syslog_port: 5514,
        wal_max_disk_mb: 2048,
        tls_skip_verify: false,
        health: {
          alloy_status: "disabled",
          pve_exporter_status: "disabled",
          wal_usage_bytes: 0,
          local_targets_count: 0,
        },
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core"]),
  },
  created() {
    this.refreshAll();
  },
  methods: {
    refreshAll() {
      this.fetchCoreStatus();
      this.fetchCollectorConfig();
    },
    async fetchCoreStatus() {
      if (!this.instanceName) {
        return;
      }
      this.loadingStatus = true;
      const taskAction = "get-status";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.loadingStatus = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (taskContext, taskResult) => {
          const output = (taskResult && taskResult.output) || (taskContext && taskContext.output);
          if (output) {
            this.coreStatus = output;
          }
          this.loadingStatus = false;
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action.get-status"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.loadingStatus = false;
      }
    },
    async fetchCollectorConfig() {
      if (!this.instanceName) {
        return;
      }
      this.loadingConfig = true;
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.loadingConfig = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (taskContext, taskResult) => {
          const output = (taskResult && taskResult.output) || (taskContext && taskContext.output);
          if (output) {
            this.config = output;
          }
          this.loadingConfig = false;
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
        this.loadingConfig = false;
      }
    },
    healthBadgeKind(status) {
      if (status === "healthy") return "green";
      if (status === "unhealthy") return "red";
      return "gray";
    },
    healthStatusLabel(status) {
      if (status === "healthy") return this.$t("common.healthy");
      if (status === "unhealthy") return this.$t("common.unhealthy");
      return this.$t("common.disabled");
    },
    formatBytes(bytes) {
      const val = Number(bytes) || 0;
      if (val < 1024) return `${val} B`;
      const units = ["KiB", "MiB", "GiB", "TiB"];
      let cur = val / 1024;
      let idx = 0;
      while (cur >= 1024 && idx < units.length - 1) {
        cur /= 1024;
        idx += 1;
      }
      return `${cur.toFixed(1)} ${units[idx]}`;
    },
  },
};
</script>

