<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("status.title") }}</h1>
      <div class="page-toolbar__actions">
        <NsButton
          kind="secondary"
          size="field"
          :icon="Renew20"
          :disabled="loadingOverview || loadingStatus"
          @click="refreshAll"
        >
          {{ $t("common.refresh") }}
        </NsButton>
        <NsButton
          v-if="overview.configured && overview.grafana_url"
          kind="ghost"
          size="field"
          :icon="Launch20"
          @click="openGrafanaPath('/d/ns8-pods-and-modules?orgId=1')"
        >
          {{ $t("status.open_ns8_pods_dashboard") }}
        </NsButton>
        <NsButton
          v-if="overview.configured && overview.grafana_url"
          kind="ghost"
          size="field"
          :icon="Launch20"
          @click="openGrafanaPath('/d/central-log-explorer?orgId=1')"
        >
          {{ $t("status.open_log_explorer_dashboard") }}
        </NsButton>
        <NsButton
          kind="primary"
          size="field"
          :icon="Launch20"
          :disabled="!overview.configured || !overview.grafana_url"
          @click="openGrafana"
        >
          {{ $t("status.open_grafana") }}
        </NsButton>
      </div>
    </div>

    <NsInlineNotification
      v-if="errorMessage"
      kind="error"
      :title="$t('status.error_loading_status')"
      :description="errorMessage"
      :showCloseButton="true"
      @close="errorMessage = ''"
      class="mg-bottom-md"
    />

    <NsInlineNotification
      v-if="copiedEndpoint"
      kind="success"
      :title="$t('common.copied_to_clipboard')"
      :description="copiedEndpoint"
      :showCloseButton="true"
      @close="copiedEndpoint = ''"
      class="mg-bottom-md"
    />

    <!-- KPI Summary Row -->
    <div class="kpi-grid" role="region" :aria-label="$t('status.kpi_region')">
      <div class="kpi-tile">
        <div>
          <div class="kpi-tile__label">{{ $t("status.active_series") }}</div>
          <cv-skeleton-text v-if="loadingOverview" :width="'60%'" heading />
          <div v-else class="kpi-tile__value">
            {{ overview.counts.active_series | humanFormat }}
          </div>
        </div>
        <div class="kpi-tile__meta">
          <NsTag
            :kind="overview.storage_mode === 's3' ? 'blue' : 'gray'"
            :label="
              overview.storage_mode === 's3'
                ? $t('status.storage_s3_thanos')
                : $t('status.storage_local')
            "
          />
          <span v-if="overview.storage_mode === 's3' && overview.s3_bucket">
            {{ overview.s3_bucket }}
          </span>
        </div>
      </div>

      <div class="kpi-tile">
        <div>
          <div class="kpi-tile__label">{{ $t("status.tenants_count") }}</div>
          <cv-skeleton-text v-if="loadingOverview" :width="'45%'" heading />
          <div v-else class="kpi-tile__value">
            {{ overview.counts.tenants }}
          </div>
        </div>
        <div class="kpi-tile__meta">
          <span>
            {{
              $t("status.portals_active", {
                count: overview.counts.portal_enabled_tenants,
              })
            }}
          </span>
        </div>
      </div>

      <div class="kpi-tile">
        <div>
          <div class="kpi-tile__label">{{ $t("status.central_targets") }}</div>
          <cv-skeleton-text v-if="loadingOverview" :width="'45%'" heading />
          <div v-else class="kpi-tile__value">
            {{ overview.counts.central_targets }}
          </div>
        </div>
        <div class="kpi-tile__meta">
          <span>{{ $t("status.central_targets_hint") }}</span>
        </div>
      </div>

      <div class="kpi-tile">
        <div>
          <div class="kpi-tile__label">{{ $t("status.firing_alerts") }}</div>
          <cv-skeleton-text v-if="loadingOverview" :width="'45%'" heading />
          <div v-else class="kpi-tile__value">
            {{ totalFiringAlerts }}
          </div>
        </div>
        <div class="kpi-tile__meta">
          <NsTag
            :kind="overview.counts.firing_alerts_critical > 0 ? 'red' : 'gray'"
            :label="
              $t('status.critical_count', {
                count: overview.counts.firing_alerts_critical,
              })
            "
          />
          <NsTag
            :kind="
              overview.counts.firing_alerts_warning > 0 ? 'warm-gray' : 'gray'
            "
            :label="
              $t('status.warning_count', {
                count: overview.counts.firing_alerts_warning,
              })
            "
          />
          <span>
            {{
              $t("status.silences_active", {
                count: overview.counts.active_silences,
              })
            }}
          </span>
        </div>
      </div>
    </div>

    <!-- Storage Usage & HTTPS Endpoints -->
    <section class="section-card">
      <div class="section-card__header">
        <div>
          <h2 class="section-card__title">
            {{ $t("status.storage_and_endpoints") }}
          </h2>
          <p class="section-card__subtitle">
            {{
              overview.storage_mode === "s3"
                ? $t("status.storage_s3_desc")
                : $t("status.storage_local_desc")
            }}
          </p>
        </div>
        <NsTag
          :kind="overview.storage_mode === 's3' ? 'blue' : 'green'"
          :label="
            overview.storage_mode === 's3'
              ? $t('status.mode_s3_badge')
              : $t('status.mode_local_badge')
          "
        />
      </div>

      <div class="storage-breakdown mg-bottom-md">
        <div class="storage-stat">
          <div class="storage-stat__label">
            {{ $t("status.prometheus_disk") }}
          </div>
          <div class="storage-stat__value">
            {{ overview.storage_usage_bytes.prometheus_bytes | byteFormat }}
          </div>
        </div>
        <div class="storage-stat">
          <div class="storage-stat__label">{{ $t("status.loki_disk") }}</div>
          <div class="storage-stat__value">
            {{ overview.storage_usage_bytes.loki_bytes | byteFormat }}
          </div>
        </div>
        <div class="storage-stat">
          <div class="storage-stat__label">{{ $t("status.grafana_disk") }}</div>
          <div class="storage-stat__value">
            {{ overview.storage_usage_bytes.grafana_bytes | byteFormat }}
          </div>
        </div>
        <div class="storage-stat">
          <div class="storage-stat__label">{{ $t("status.total_disk") }}</div>
          <div class="storage-stat__value">
            {{ overview.storage_usage_bytes.total_bytes | byteFormat }}
          </div>
        </div>
      </div>

      <div v-if="overview.configured">
        <div class="endpoint-row" v-if="overview.grafana_url">
          <div>
            <strong>{{ $t("status.grafana_endpoint") }}:</strong>
            {{ overview.grafana_url }}
          </div>
          <NsButton
            kind="ghost"
            size="sm"
            :icon="Copy16"
            @click="copyText(overview.grafana_url)"
          >
            {{ $t("common.copy") }}
          </NsButton>
        </div>
        <div class="endpoint-row" v-if="overview.ingest_metrics_url">
          <div>
            <strong>{{ $t("status.metrics_ingest_endpoint") }}:</strong>
            {{ overview.ingest_metrics_url }}
          </div>
          <NsButton
            kind="ghost"
            size="sm"
            :icon="Copy16"
            @click="copyText(overview.ingest_metrics_url)"
          >
            {{ $t("common.copy") }}
          </NsButton>
        </div>
        <div class="endpoint-row" v-if="overview.ingest_logs_url">
          <div>
            <strong>{{ $t("status.logs_ingest_endpoint") }}:</strong>
            {{ overview.ingest_logs_url }}
          </div>
          <NsButton
            kind="ghost"
            size="sm"
            :icon="Copy16"
            @click="copyText(overview.ingest_logs_url)"
          >
            {{ $t("common.copy") }}
          </NsButton>
        </div>
      </div>
    </section>

    <!-- Hub Pod Components Health -->
    <section class="section-card">
      <div class="section-card__header">
        <div>
          <h2 class="section-card__title">
            {{ $t("status.pod_components_title") }}
          </h2>
          <p class="section-card__subtitle">
            {{ $t("status.pod_components_subtitle") }}
          </p>
        </div>
      </div>

      <cv-skeleton-text v-if="loadingOverview" :paragraph="true" :line-count="4" />
      <div v-else class="component-badge-grid">
        <div
          v-for="comp in componentEntries"
          :key="comp.key"
          class="component-badge-item"
        >
          <span class="component-badge-item__name">{{ comp.label }}</span>
          <span class="table-row-actions">
            <CheckmarkFilled16
              v-if="comp.state === 'healthy'"
              aria-hidden="true"
            />
            <ErrorFilled16
              v-else-if="comp.state === 'unhealthy'"
              aria-hidden="true"
            />
            <WarningFilled16 v-else aria-hidden="true" />
            <NsTag
              :kind="getComponentTagKind(comp.state)"
              :label="$t(`status.component_state_${comp.state}`)"
            />
          </span>
        </div>
      </div>
    </section>

    <!-- Core NS8 Module Status (Node, Systemd Units, Images, Volumes) -->
    <section class="section-card">
      <div class="section-card__header">
        <div>
          <h2 class="section-card__title">
            {{ $t("status.ns8_runtime_title") }}
          </h2>
          <p class="section-card__subtitle">
            {{
              $t("status.ns8_runtime_subtitle", {
                instance: status.instance || instanceName,
                node: status.node_ui_name || status.node || "-",
              })
            }}
          </p>
        </div>
      </div>

      <cv-skeleton-text v-if="loadingStatus" :paragraph="true" :line-count="4" />
      <div v-else class="form-grid-2">
        <div>
          <h3 class="form-section-title">
            {{ $t("status.systemd_services") }} ({{ status.services.length }})
          </h3>
          <div
            v-if="!status.services.length"
            class="form-section-desc"
          >
            {{ $t("status.no_services_reported") }}
          </div>
          <div
            v-for="svc in status.services"
            :key="svc.name"
            class="component-badge-item mg-bottom-sm"
          >
            <span class="mono-text">{{ svc.name }}</span>
            <NsTag
              :kind="
                svc.failed ? 'red' : svc.active ? 'green' : 'gray'
              "
              :label="
                svc.failed
                  ? $t('status.service_failed')
                  : svc.active
                  ? $t('status.service_active')
                  : $t('status.service_inactive')
              "
            />
          </div>
        </div>

        <div>
          <h3 class="form-section-title">
            {{ $t("status.container_images") }} ({{ status.images.length }})
          </h3>
          <div
            v-if="!status.images.length"
            class="form-section-desc"
          >
            {{ $t("status.no_images_reported") }}
          </div>
          <div
            v-for="img in status.images"
            :key="img.name"
            class="component-badge-item mg-bottom-sm"
          >
            <span class="mono-text">{{ img.name }}</span>
            <NsTag kind="gray" :label="img.size | byteFormat" />
          </div>

          <h3
            v-if="status.volumes && status.volumes.length"
            class="form-section-title mg-top-md"
          >
            {{ $t("status.podman_volumes") }} ({{ status.volumes.length }})
          </h3>
          <div
            v-for="vol in status.volumes"
            :key="vol.name"
            class="component-badge-item mg-bottom-sm"
          >
            <span class="mono-text">{{ vol.name }}</span>
            <span class="form-section-desc">{{ vol.created || "" }}</span>
          </div>
        </div>
      </div>
    </section>
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
import Launch20 from "@carbon/icons-vue/es/launch/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Copy16 from "@carbon/icons-vue/es/copy/16";
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import ErrorFilled16 from "@carbon/icons-vue/es/error--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";

const COMPONENT_KEYS = [
  "hub_gateway",
  "prometheus",
  "loki",
  "grafana",
  "alertmanager",
  "prom_label_proxy",
  "blackbox_exporter",
  "snmp_exporter",
  "thanos_sidecar",
  "thanos_store",
  "thanos_query",
];

export default {
  name: "Status",
  components: {
    CheckmarkFilled16,
    ErrorFilled16,
    WarningFilled16,
  },
  mixins: [TaskService, IconService, UtilService, PageTitleService],
  pageTitle() {
    return `${this.$t("status.title")} - ${this.appName}`;
  },
  data() {
    return {
      Launch20,
      Renew20,
      Copy16,
      loadingStatus: false,
      loadingOverview: false,
      errorMessage: "",
      copiedEndpoint: "",
      status: {
        instance: "",
        ui_name: "",
        node: null,
        node_ui_name: "",
        services: [],
        images: [],
        volumes: [],
      },
      overview: {
        configured: true,
        grafana_url: "",
        ingest_metrics_url: "",
        ingest_logs_url: "",
        storage_mode: "local",
        s3_bucket: "",
        components: {
          hub_gateway: "disabled",
          prometheus: "disabled",
          loki: "disabled",
          grafana: "disabled",
          alertmanager: "disabled",
          prom_label_proxy: "disabled",
          blackbox_exporter: "disabled",
          snmp_exporter: "disabled",
          thanos_sidecar: "disabled",
          thanos_store: "disabled",
          thanos_query: "disabled",
        },
        counts: {
          tenants: 0,
          portal_enabled_tenants: 0,
          central_targets: 0,
          active_series: 0,
          firing_alerts_critical: 0,
          firing_alerts_warning: 0,
          active_silences: 0,
        },
        storage_usage_bytes: {
          prometheus_bytes: 0,
          loki_bytes: 0,
          grafana_bytes: 0,
          total_bytes: 0,
        },
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "appName", "core"]),
    totalFiringAlerts() {
      return (
        (this.overview.counts.firing_alerts_critical || 0) +
        (this.overview.counts.firing_alerts_warning || 0)
      );
    },
    componentEntries() {
      return COMPONENT_KEYS.map((key) => ({
        key,
        label: this.$t(`status.components.${key}`),
        state:
          (this.overview.components && this.overview.components[key]) ||
          "disabled",
      }));
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.refreshAll();
        }
      },
    },
  },
  methods: {
    ...mapActions(["setAppConfiguredInStore", "setGrafanaUrlInStore"]),
    refreshAll() {
      this.errorMessage = "";
      this.getStatus();
      this.getOverview();
    },
    getComponentTagKind(state) {
      if (state === "healthy") {
        return "green";
      }
      if (state === "unhealthy") {
        return "red";
      }
      return "gray";
    },
    openGrafana() {
      if (this.overview.grafana_url) {
        const clean = this.overview.grafana_url.replace(/\/+$/, "");
        const targetUrl = clean.includes("orgId=")
          ? clean
          : `${clean}${clean.includes("?") ? "&" : "/?"}orgId=1`;
        window.open(targetUrl, "_blank", "noopener,noreferrer");
      }
    },
    openGrafanaPath(subpath) {
      if (this.overview.grafana_url && subpath) {
        const clean = this.overview.grafana_url.replace(/\/+$/, "");
        const normalizedPath = subpath.startsWith("/")
          ? subpath
          : `/${subpath}`;
        window.open(
          `${clean}${normalizedPath}`,
          "_blank",
          "noopener,noreferrer"
        );
      }
    },
    async copyText(value) {
      if (!value) {
        return;
      }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(value);
        }
        this.copiedEndpoint = value;
      } catch (err) {
        this.copiedEndpoint = value;
      }
    },
    async getStatus() {
      this.loadingStatus = true;
      const taskAction = "get-status";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.getStatusAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.getStatusCompleted
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
        this.loadingStatus = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    getStatusAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loadingStatus = false;
      this.errorMessage = this.$t("error.cannot_retrieve_module_info");
      this.createErrorNotificationForApp(
        taskError,
        this.$t("error.cannot_retrieve_module_info")
      );
    },
    getStatusCompleted(taskContext, taskResult) {
      this.loadingStatus = false;
      const output = (taskResult && taskResult.output) || {};
      this.status = {
        instance: output.instance || this.instanceName,
        ui_name: output.ui_name || "",
        node: output.node || null,
        node_ui_name: output.node_ui_name || "",
        services: Array.isArray(output.services) ? output.services : [],
        images: Array.isArray(output.images) ? output.images : [],
        volumes: Array.isArray(output.volumes) ? output.volumes : [],
      };
    },
    async getOverview() {
      this.loadingOverview = true;
      const taskAction = "get-overview";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.getOverviewAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.getOverviewCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {},
          extra: {
            title: this.$t("action.get-overview"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.loadingOverview = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    getOverviewAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loadingOverview = false;
      this.errorMessage = this.$t("status.cannot_retrieve_overview");
      this.createErrorNotificationForApp(
        taskError,
        this.$t("status.cannot_retrieve_overview")
      );
    },
    getOverviewCompleted(taskContext, taskResult) {
      this.loadingOverview = false;
      const out = (taskResult && taskResult.output) || {};
      this.overview = {
        configured: Boolean(out.configured),
        grafana_url: out.grafana_url || "",
        ingest_metrics_url: out.ingest_metrics_url || "",
        ingest_logs_url: out.ingest_logs_url || "",
        storage_mode: out.storage_mode === "s3" ? "s3" : "local",
        s3_bucket: out.s3_bucket || "",
        components: Object.assign(
          {},
          this.overview.components,
          out.components || {}
        ),
        counts: Object.assign({}, this.overview.counts, out.counts || {}),
        storage_usage_bytes: Object.assign(
          {},
          this.overview.storage_usage_bytes,
          out.storage_usage_bytes || {}
        ),
      };
      this.setAppConfiguredInStore(this.overview.configured);
      this.setGrafanaUrlInStore(this.overview.grafana_url);
    },
  },
};
</script>
