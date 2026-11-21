<template>
  <div class="bx--grid bx--grid--full-width bx--no-gutter">
    <div class="collector-page-header">
      <div>
        <h1 class="collector-page-title">{{ $t("targets.title") }}</h1>
        <p class="collector-page-subtitle">{{ $t("targets.subtitle") }}</p>
      </div>
      <div class="header-actions">
        <NsButton
          kind="tertiary"
          size="field"
          :icon="Renew20"
          :disabled="loading"
          @click="loadTargets"
        >
          {{ $t("common.refresh") }}
        </NsButton>
        <NsButton kind="primary" size="field" :icon="Add20" @click="openCreateModal">
          {{ $t("targets.add_target") }}
        </NsButton>
      </div>
    </div>

    <div v-if="feedbackBanner.visible" class="collector-section-gap">
      <NsInlineNotification
        :kind="feedbackBanner.kind"
        :title="feedbackBanner.title"
        :description="feedbackBanner.description"
        :showCloseButton="true"
        @close="feedbackBanner.visible = false"
      />
    </div>

    <div class="collector-card collector-section-gap">
      <div class="filter-toolbar">
        <div class="filter-select-wrap">
          <cv-select
            v-model="filterType"
            :label="$t('targets.filter_type')"
            @change="loadTargets"
          >
            <cv-select-option value="">{{ $t("targets.all_types") }}</cv-select-option>
            <cv-select-option value="proxmox">{{ $t("targets.type_proxmox") }}</cv-select-option>
            <cv-select-option value="windows">{{ $t("targets.type_windows") }}</cv-select-option>
            <cv-select-option value="linux">{{ $t("targets.type_linux") }}</cv-select-option>
            <cv-select-option value="snmp">{{ $t("targets.type_snmp") }}</cv-select-option>
            <cv-select-option value="custom-exporter">
              {{ $t("targets.type_custom_exporter") }}
            </cv-select-option>
          </cv-select>
        </div>
        <div class="filter-search-wrap">
          <cv-search
            v-model="searchQuery"
            :label="$t('common.search')"
            :placeholder="$t('targets.search_placeholder')"
          />
        </div>
      </div>

      <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="5" />

      <div v-else-if="filteredTargets.length === 0" class="empty-targets-box" role="status">
        <Network_220 class="empty-icon" />
        <h2 class="empty-heading">{{ $t("targets.empty_title") }}</h2>
        <p class="empty-desc">{{ $t("targets.empty_description") }}</p>
        <NsButton kind="primary" :icon="Add20" @click="openCreateModal">
          {{ $t("targets.add_target") }}
        </NsButton>
      </div>

      <div v-else class="table-scroll-container">
        <table class="bx--data-table bx--data-table--compact">
          <thead>
            <tr>
              <th>{{ $t("targets.col_name") }}</th>
              <th>{{ $t("targets.col_type") }}</th>
              <th>{{ $t("targets.col_role") }}</th>
              <th>{{ $t("targets.col_endpoint") }}</th>
              <th>{{ $t("targets.col_interval") }}</th>
              <th>{{ $t("targets.col_credentials") }}</th>
              <th>{{ $t("targets.col_status") }}</th>
              <th>{{ $t("targets.col_actions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in filteredTargets" :key="item.id">
              <td><strong>{{ item.name }}</strong></td>
              <td>{{ formatTargetType(item.target_type) }}</td>
              <td><code>{{ item.device_role }}</code></td>
              <td><code>{{ item.host }}:{{ item.port }}</code></td>
              <td>{{ item.scrape_interval }}</td>
              <td>
                <cv-tag
                  v-if="item.has_pve_token_secret || item.has_snmp_secret"
                  kind="teal"
                  :label="$t('targets.secret_configured')"
                />
                <span v-else>{{ $t("targets.secret_none") }}</span>
              </td>
              <td>
                <cv-tag
                  :kind="item.enabled ? 'green' : 'gray'"
                  :label="item.enabled ? $t('common.enabled') : $t('common.disabled')"
                />
              </td>
              <td class="row-action-buttons">
                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="Edit20"
                  @click="openEditModal(item)"
                >
                  {{ $t("common.edit") }}
                </NsButton>
                <NsButton
                  kind="danger--ghost"
                  size="small"
                  :icon="TrashCan20"
                  @click="openDeleteModal(item)"
                >
                  {{ $t("common.delete") }}
                </NsButton>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <NsModal
      size="default"
      :visible="modalVisible"
      :primary-button-disabled="saving"
      @modal-hidden="closeModal"
      @primary-click="submitTargetForm"
    >
      <template slot="title">
        {{ isEditing ? $t("targets.edit_target") : $t("targets.add_target") }}
      </template>
      <template slot="content">
        <cv-form @submit.prevent="submitTargetForm">
          <NsTextInput
            v-model.trim="form.name"
            :label="$t('targets.field_name')"
            :placeholder="$t('targets.field_name_placeholder')"
            :invalid-message="validationErrors.name"
            required
          />

          <div class="modal-row-2col">
            <cv-select
              v-model="form.target_type"
              :label="$t('targets.field_target_type')"
              @change="onTargetTypeChange"
            >
              <cv-select-option value="proxmox">{{ $t("targets.type_proxmox") }}</cv-select-option>
              <cv-select-option value="windows">{{ $t("targets.type_windows") }}</cv-select-option>
              <cv-select-option value="linux">{{ $t("targets.type_linux") }}</cv-select-option>
              <cv-select-option value="snmp">{{ $t("targets.type_snmp") }}</cv-select-option>
              <cv-select-option value="custom-exporter">
                {{ $t("targets.type_custom_exporter") }}
              </cv-select-option>
            </cv-select>

            <cv-select v-model="form.device_role" :label="$t('targets.field_device_role')">
              <cv-select-option v-for="role in roleOptions" :key="role" :value="role">
                {{ role }}
              </cv-select-option>
            </cv-select>
          </div>

          <div class="modal-row-2col">
            <NsTextInput
              v-model.trim="form.host"
              :label="$t('targets.field_host')"
              :placeholder="$t('targets.field_host_placeholder')"
              :invalid-message="validationErrors.host"
              required
            />
            <NsTextInput
              v-model.number="form.port"
              type="number"
              :label="$t('targets.field_port')"
              :invalid-message="validationErrors.port"
            />
          </div>

          <div class="modal-row-2col">
            <cv-select v-model="form.scrape_interval" :label="$t('targets.field_scrape_interval')">
              <cv-select-option value="15s">15s</cv-select-option>
              <cv-select-option value="30s">30s</cv-select-option>
              <cv-select-option value="60s">60s</cv-select-option>
              <cv-select-option value="120s">120s</cv-select-option>
              <cv-select-option value="300s">300s</cv-select-option>
            </cv-select>

            <cv-select
              v-if="form.target_type !== 'snmp' && form.target_type !== 'proxmox'"
              v-model="form.scheme"
              :label="$t('targets.field_scheme')"
            >
              <cv-select-option value="http">http</cv-select-option>
              <cv-select-option value="https">https</cv-select-option>
            </cv-select>
          </div>

          <div v-if="form.target_type === 'custom-exporter'" class="modal-field-gap">
            <NsTextInput
              v-model.trim="form.metrics_path"
              :label="$t('targets.field_metrics_path')"
              placeholder="/metrics"
              :invalid-message="validationErrors.metrics_path"
            />
          </div>

          <div v-if="form.target_type === 'proxmox'" class="type-specific-panel">
            <NsTextInput
              v-model.trim="form.pve_token_id"
              :label="$t('targets.field_pve_token_id')"
              :placeholder="$t('targets.field_pve_token_id_placeholder')"
              :invalid-message="validationErrors.pve_token_id"
            />
            <NsPasswordInput
              v-model="form.pve_token_secret"
              :label="$t('targets.field_pve_token_secret')"
              :helper-text="isEditing ? $t('targets.field_pve_token_secret_keep') : ''"
              :invalid-message="validationErrors.pve_token_secret"
            />
            <cv-checkbox
              v-model="form.tls_skip_verify"
              value="tls_skip_verify"
              :label="$t('targets.field_tls_skip_verify')"
            />
          </div>

          <div v-if="form.target_type === 'snmp'" class="type-specific-panel">
            <div class="modal-row-2col">
              <cv-select
                v-model="form.snmp_module"
                :label="$t('targets.field_snmp_module')"
                @change="onSnmpModuleChange"
              >
                <cv-select-option value="if_mib">{{ $t("targets.snmp_mod_if_mib") }}</cv-select-option>
                <cv-select-option value="apcupsd">{{ $t("targets.snmp_mod_apcupsd") }}</cv-select-option>
                <cv-select-option value="synology">{{ $t("targets.snmp_mod_synology") }}</cv-select-option>
                <cv-select-option value="qnap">{{ $t("targets.snmp_mod_qnap") }}</cv-select-option>
                <cv-select-option value="printer">{{ $t("targets.snmp_mod_printer") }}</cv-select-option>
                <cv-select-option value="generic">{{ $t("targets.snmp_mod_generic") }}</cv-select-option>
              </cv-select>

              <cv-select v-model="form.snmp_version" :label="$t('targets.field_snmp_version')">
                <cv-select-option value="v2c">SNMP v2c</cv-select-option>
                <cv-select-option value="v3">SNMP v3</cv-select-option>
              </cv-select>
            </div>

            <div v-if="form.snmp_version === 'v2c'" class="modal-field-gap">
              <NsPasswordInput
                v-model="form.snmp_community"
                :label="$t('targets.field_snmp_community')"
                :helper-text="isEditing ? $t('targets.field_snmp_community_keep') : ''"
              />
            </div>

            <div v-else class="modal-field-gap">
              <div class="modal-row-2col">
                <NsTextInput
                  v-model.trim="form.snmp_v3.username"
                  :label="$t('targets.field_snmp_v3_username')"
                />
                <cv-select
                  v-model="form.snmp_v3.security_level"
                  :label="$t('targets.field_snmp_v3_security_level')"
                >
                  <cv-select-option value="authPriv">authPriv</cv-select-option>
                  <cv-select-option value="authNoPriv">authNoPriv</cv-select-option>
                  <cv-select-option value="noAuthNoPriv">noAuthNoPriv</cv-select-option>
                </cv-select>
              </div>
              <div class="modal-row-2col">
                <cv-select
                  v-model="form.snmp_v3.auth_protocol"
                  :label="$t('targets.field_snmp_v3_auth_protocol')"
                >
                  <cv-select-option value="SHA256">SHA256</cv-select-option>
                  <cv-select-option value="SHA384">SHA384</cv-select-option>
                  <cv-select-option value="SHA512">SHA512</cv-select-option>
                  <cv-select-option value="SHA224">SHA224</cv-select-option>
                  <cv-select-option value="SHA">SHA</cv-select-option>
                  <cv-select-option value="MD5">MD5</cv-select-option>
                </cv-select>
                <NsPasswordInput
                  v-model="form.snmp_v3.auth_password"
                  :label="$t('targets.field_snmp_v3_auth_password')"
                />
              </div>
              <div class="modal-row-2col">
                <cv-select
                  v-model="form.snmp_v3.priv_protocol"
                  :label="$t('targets.field_snmp_v3_priv_protocol')"
                >
                  <cv-select-option value="AES">AES</cv-select-option>
                  <cv-select-option value="AES192">AES192</cv-select-option>
                  <cv-select-option value="AES256">AES256</cv-select-option>
                  <cv-select-option value="DES">DES</cv-select-option>
                </cv-select>
                <NsPasswordInput
                  v-model="form.snmp_v3.priv_password"
                  :label="$t('targets.field_snmp_v3_priv_password')"
                />
              </div>
            </div>
          </div>

          <div
            v-if="form.target_type !== 'proxmox' && form.scheme === 'https'"
            class="modal-field-gap"
          >
            <cv-checkbox
              v-model="form.tls_skip_verify"
              value="tls_skip_verify_http"
              :label="$t('targets.field_tls_skip_verify')"
            />
          </div>

          <div class="modal-field-gap">
            <cv-checkbox
              v-model="form.enabled"
              value="target_enabled"
              :label="$t('targets.field_enabled')"
            />
          </div>
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("common.save") }}</template>
    </NsModal>

    <NsModal
      kind="danger"
      size="small"
      :visible="deleteModalVisible"
      :primary-button-disabled="deleting"
      @modal-hidden="deleteModalVisible = false"
      @primary-click="confirmDeleteTarget"
    >
      <template slot="title">{{ $t("targets.delete_target") }}</template>
      <template slot="content">
        <p v-if="targetToDelete">
          {{
            $t("targets.delete_confirm_message", {
              name: targetToDelete.name,
              host: targetToDelete.host,
            })
          }}
        </p>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("common.delete") }}</template>
    </NsModal>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { TaskService, IconService, UtilService } from "@nethserver/ns8-ui-lib";
import Add20 from "@carbon/icons-vue/es/add/20";
import Edit20 from "@carbon/icons-vue/es/edit/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Network_220 from "@carbon/icons-vue/es/network--2/20";

const DEFAULT_PORTS_BY_TYPE = {
  proxmox: 8006,
  windows: 9182,
  linux: 9100,
  snmp: 161,
  "custom-exporter": 9100,
};

const DEFAULT_ROLES_BY_TYPE = {
  proxmox: "proxmox",
  windows: "windows",
  linux: "linux",
  snmp: "snmp-network",
  "custom-exporter": "linux",
};

function emptyTargetForm() {
  return {
    id: "",
    name: "",
    enabled: true,
    target_type: "proxmox",
    device_role: "proxmox",
    host: "",
    port: 8006,
    scrape_interval: "60s",
    scheme: "https",
    metrics_path: "/metrics",
    tls_skip_verify: true,
    pve_token_id: "monitoring@pve!alloy",
    pve_token_secret: "",
    snmp_module: "if_mib",
    snmp_version: "v2c",
    snmp_community: "public",
    snmp_v3: {
      username: "",
      security_level: "authPriv",
      auth_protocol: "SHA256",
      auth_password: "",
      priv_protocol: "AES",
      priv_password: "",
    },
  };
}

export default {
  name: "LocalTargets",
  components: {
    Network_220,
  },
  mixins: [TaskService, IconService, UtilService],
  data() {
    return {
      Add20,
      Edit20,
      TrashCan20,
      Renew20,
      loading: false,
      saving: false,
      deleting: false,
      targets: [],
      filterType: "",
      searchQuery: "",
      modalVisible: false,
      isEditing: false,
      form: emptyTargetForm(),
      validationErrors: {},
      deleteModalVisible: false,
      targetToDelete: null,
      feedbackBanner: {
        visible: false,
        kind: "success",
        title: "",
        description: "",
      },
      roleOptions: [
        "proxmox",
        "windows",
        "linux",
        "snmp-network",
        "snmp-firewall",
        "snmp-ups",
        "snmp-nas",
        "snmp-printer",
        "web",
        "ns8",
      ],
    };
  },
  computed: {
    ...mapState(["instanceName", "core"]),
    filteredTargets() {
      const q = (this.searchQuery || "").trim().toLowerCase();
      if (!q) return this.targets;
      return this.targets.filter(
        (t) =>
          (t.name && t.name.toLowerCase().includes(q)) ||
          (t.host && t.host.toLowerCase().includes(q)) ||
          (t.device_role && t.device_role.toLowerCase().includes(q))
      );
    },
  },
  created() {
    this.loadTargets();
  },
  methods: {
    formatTargetType(ttype) {
      const map = {
        proxmox: this.$t("targets.type_proxmox"),
        windows: this.$t("targets.type_windows"),
        linux: this.$t("targets.type_linux"),
        snmp: this.$t("targets.type_snmp"),
        "custom-exporter": this.$t("targets.type_custom_exporter"),
      };
      return map[ttype] || ttype;
    },
    onTargetTypeChange() {
      const t = this.form.target_type;
      this.form.port = DEFAULT_PORTS_BY_TYPE[t] || 9100;
      this.form.device_role = DEFAULT_ROLES_BY_TYPE[t] || "linux";
      this.form.scheme = t === "proxmox" ? "https" : "http";
      this.form.scrape_interval = t === "proxmox" || t === "snmp" ? "60s" : "30s";
    },
    onSnmpModuleChange() {
      const roleByMod = {
        if_mib: "snmp-network",
        apcupsd: "snmp-ups",
        synology: "snmp-nas",
        qnap: "snmp-nas",
        printer: "snmp-printer",
        generic: "snmp-network",
      };
      if (roleByMod[this.form.snmp_module]) {
        this.form.device_role = roleByMod[this.form.snmp_module];
      }
    },
    openCreateModal() {
      this.isEditing = false;
      this.validationErrors = {};
      this.form = emptyTargetForm();
      this.modalVisible = true;
    },
    openEditModal(item) {
      this.isEditing = true;
      this.validationErrors = {};
      const v3Meta = item.snmp_v3 || {};
      this.form = {
        ...emptyTargetForm(),
        id: item.id,
        name: item.name,
        enabled: item.enabled,
        target_type: item.target_type,
        device_role: item.device_role,
        host: item.host,
        port: item.port,
        scrape_interval: item.scrape_interval || "30s",
        scheme: item.scheme || "http",
        metrics_path: item.metrics_path || "/metrics",
        tls_skip_verify: Boolean(item.tls_skip_verify),
        pve_token_id: item.pve_token_id || "monitoring@pve!alloy",
        pve_token_secret: "",
        snmp_module: item.snmp_module || "if_mib",
        snmp_version: item.snmp_version || "v2c",
        snmp_community: "",
        snmp_v3: {
          username: v3Meta.username || "",
          security_level: v3Meta.security_level || "authPriv",
          auth_protocol: v3Meta.auth_protocol || "SHA256",
          auth_password: "",
          priv_protocol: v3Meta.priv_protocol || "AES",
          priv_password: "",
        },
      };
      this.modalVisible = true;
    },
    closeModal() {
      this.modalVisible = false;
    },
    openDeleteModal(item) {
      this.targetToDelete = item;
      this.deleteModalVisible = true;
    },
    async loadTargets() {
      if (!this.instanceName) return;
      this.loading = true;
      const taskAction = "list-local-targets";
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
          this.targets = output && Array.isArray(output.targets) ? output.targets : [];
          this.loading = false;
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { target_type: this.filterType || "" },
          extra: {
            title: this.$t("action.list-local-targets"),
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
    buildSavePayload() {
      const f = this.form;
      const hasNewSecret = Boolean(
        (f.target_type === "proxmox" && f.pve_token_secret) ||
          (f.target_type === "snmp" &&
            f.snmp_version === "v2c" &&
            f.snmp_community) ||
          (f.target_type === "snmp" &&
            f.snmp_version === "v3" &&
            (f.snmp_v3.auth_password || f.snmp_v3.priv_password))
      );
      const payload = {
        id: f.id || "",
        name: f.name,
        enabled: Boolean(f.enabled),
        target_type: f.target_type,
        device_role: f.device_role,
        host: f.host,
        port: Number(f.port) || DEFAULT_PORTS_BY_TYPE[f.target_type] || 9100,
        scrape_interval: f.scrape_interval || "30s",
        scheme: f.scheme || "http",
        metrics_path: f.metrics_path || "/metrics",
        tls_skip_verify: Boolean(f.tls_skip_verify),
        secret_unchanged: Boolean(this.isEditing && !hasNewSecret),
      };
      if (f.target_type === "proxmox") {
        payload.pve_token_id = f.pve_token_id;
        payload.pve_token_secret = f.pve_token_secret || "";
      } else if (f.target_type === "snmp") {
        payload.snmp_module = f.snmp_module;
        payload.snmp_version = f.snmp_version;
        if (f.snmp_version === "v2c") {
          payload.snmp_community = f.snmp_community || (this.isEditing ? "" : "public");
        } else {
          payload.snmp_v3 = { ...f.snmp_v3 };
        }
      }
      return payload;
    },
    async submitTargetForm() {
      this.validationErrors = {};
      if (!this.form.name) {
        this.validationErrors = { name: this.$t("common.required") };
        return;
      }
      if (!this.form.host) {
        this.validationErrors = { host: this.$t("common.required") };
        return;
      }

      this.saving = true;
      const taskAction = "save-local-target";
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
          this.modalVisible = false;
          this.feedbackBanner = {
            visible: true,
            kind: "success",
            title: this.$t("targets.saved_title"),
            description: this.$t("targets.saved_description"),
          };
          this.loadTargets();
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: this.buildSavePayload(),
          extra: {
            title: this.$t("action.save-local-target"),
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
    async confirmDeleteTarget() {
      if (!this.targetToDelete) return;
      this.deleting = true;
      const taskAction = "delete-local-target";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        () => {
          this.deleting = false;
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        () => {
          this.deleting = false;
          this.deleteModalVisible = false;
          this.targetToDelete = null;
          this.feedbackBanner = {
            visible: true,
            kind: "info",
            title: this.$t("targets.deleted_title"),
            description: this.$t("targets.deleted_description"),
          };
          this.loadTargets();
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { id: this.targetToDelete.id },
          extra: {
            title: this.$t("action.delete-local-target"),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
        this.deleting = false;
      }
    },
  },
};
</script>

