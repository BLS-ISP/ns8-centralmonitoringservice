<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("targets.title") }}</h1>
      <div class="page-toolbar__actions">
        <NsButton
          kind="secondary"
          size="field"
          :icon="Renew20"
          :disabled="loading"
          @click="loadTargets"
        >
          {{ $t("common.refresh") }}
        </NsButton>
        <NsButton
          kind="primary"
          size="field"
          :icon="Add20"
          @click="openCreateModal"
        >
          {{ $t("targets.create_target") }}
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

    <!-- Filter Bar (Customer & Target Type) -->
    <section class="section-card">
      <div class="form-grid-2 mg-bottom-md">
        <cv-select
          v-model="filters.customer"
          :label="$t('targets.filter_customer')"
          @change="loadTargets"
        >
          <cv-select-option value="">
            {{ $t("targets.all_customers") }}
          </cv-select-option>
          <cv-select-option
            v-for="tenant in tenants"
            :key="tenant.customer"
            :value="tenant.customer"
          >
            {{ tenant.display_name }} ({{ tenant.customer }})
          </cv-select-option>
        </cv-select>

        <cv-select
          v-model="filters.target_type"
          :label="$t('targets.filter_type')"
          @change="loadTargets"
        >
          <cv-select-option value="">
            {{ $t("targets.all_types") }}
          </cv-select-option>
          <cv-select-option value="ns8-federation">
            {{ $t("targets.types.ns8-federation") }}
          </cv-select-option>
          <cv-select-option value="exporter">
            {{ $t("targets.types.exporter") }}
          </cv-select-option>
          <cv-select-option value="blackbox">
            {{ $t("targets.types.blackbox") }}
          </cv-select-option>
          <cv-select-option value="snmp">
            {{ $t("targets.types.snmp") }}
          </cv-select-option>
        </cv-select>
      </div>

      <NsDataTable
        :allRows="targets"
        :columns="i18nTableColumns"
        :rawColumns="tableColumns"
        :isSearchable="true"
        :searchPlaceholder="$t('targets.search_placeholder')"
        :searchClearLabel="$t('common.clear_search')"
        :noSearchResultsLabel="$t('common.no_results')"
        :noSearchResultsDescription="$t('common.try_changing_search')"
        :isLoading="loading"
        :skeletonRows="5"
        :isErrorShown="!!tableError"
        :errorTitle="$t('targets.cannot_load_targets')"
        :errorDescription="tableError"
        :itemsPerPageLabel="$t('pagination.items_per_page')"
        :rangeOfTotalItemsLabel="$t('pagination.range_of_total_items')"
        :ofTotalPagesLabel="$t('pagination.of_total_pages')"
        :backwardText="$t('pagination.previous_page')"
        :forwardText="$t('pagination.next_page')"
        :pageNumberLabel="$t('pagination.page_number')"
        @updatePage="tablePage = $event"
      >
        <template slot="empty-state">
          <NsEmptyState :title="$t('targets.empty_title')">
            <template #description>
              <div>{{ $t("targets.empty_description") }}</div>
              <NsButton
                kind="primary"
                size="field"
                :icon="Add20"
                class="mg-top-md"
                @click="openCreateModal"
              >
                {{ $t("targets.create_target") }}
              </NsButton>
            </template>
          </NsEmptyState>
        </template>

        <template slot="data">
          <cv-data-table-row
            v-for="(row, rowIndex) in tablePage"
            :key="row.id || `${rowIndex}`"
            :value="row.id || `${rowIndex}`"
          >
            <cv-data-table-cell>
              <div>
                <strong>{{ row.name }}</strong>
              </div>
              <div class="mono-text">{{ row.device_role }}</div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <NsTag
                kind="blue"
                :label="$t(`targets.types.${row.target_type}`)"
              />
              <div
                v-if="row.target_type === 'blackbox' && row.blackbox_module"
                class="mono-text"
              >
                {{ row.blackbox_module }}
              </div>
              <div
                v-else-if="row.target_type === 'snmp' && row.snmp_module"
                class="mono-text"
              >
                {{ row.snmp_module }} ({{ row.snmp_version || "v2c" }})
              </div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <div class="mono-text">{{ row.customer }}</div>
              <NsTag kind="gray" :label="row.site" />
            </cv-data-table-cell>

            <cv-data-table-cell>
              <div
                v-for="ep in (row.endpoints || []).slice(0, 3)"
                :key="ep"
                class="mono-text"
              >
                {{ ep }}
              </div>
              <div v-if="row.endpoints && row.endpoints.length > 3">
                +{{ row.endpoints.length - 3 }}
              </div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <span class="mono-text">{{ row.scrape_interval }}</span>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <NsTag
                :kind="row.enabled ? 'green' : 'gray'"
                :label="
                  row.enabled ? $t('common.enabled') : $t('common.disabled')
                "
              />
            </cv-data-table-cell>

            <cv-data-table-cell>
              <div class="table-row-actions">
                <NsButton
                  kind="ghost"
                  size="sm"
                  :icon="Edit16"
                  @click="openEditModal(row)"
                >
                  {{ $t("common.edit") }}
                </NsButton>
                <NsButton
                  kind="danger-ghost"
                  size="sm"
                  :icon="TrashCan16"
                  @click="openDeleteModal(row)"
                >
                  {{ $t("common.delete") }}
                </NsButton>
              </div>
            </cv-data-table-cell>
          </cv-data-table-row>
        </template>
      </NsDataTable>
    </section>

    <!-- Create / Edit Target Modal -->
    <NsModal
      size="large"
      :visible="showSaveModal"
      :primary-button-disabled="savingTarget"
      :isLoading="savingTarget"
      @modal-hidden="showSaveModal = false"
      @primary-click="submitSaveTarget"
    >
      <template slot="title">
        {{
          isEditing
            ? $t("targets.edit_target_title", { name: form.name })
            : $t("targets.create_target")
        }}
      </template>
      <template slot="content">
        <cv-form @submit.prevent="submitSaveTarget">
          <div class="form-grid-2">
            <NsTextInput
              v-model.trim="form.name"
              :label="$t('targets.name_label')"
              placeholder="ACME Web Portal HTTPS Probe"
              :disabled="savingTarget"
              :invalid-message="validationErrors.name"
            />

            <cv-select
              v-model="form.target_type"
              :label="$t('targets.type_label')"
              :disabled="savingTarget"
              @change="onTargetTypeChange"
            >
              <cv-select-option value="ns8-federation">
                {{ $t("targets.types.ns8-federation") }}
              </cv-select-option>
              <cv-select-option value="exporter">
                {{ $t("targets.types.exporter") }}
              </cv-select-option>
              <cv-select-option value="blackbox">
                {{ $t("targets.types.blackbox") }}
              </cv-select-option>
              <cv-select-option value="snmp">
                {{ $t("targets.types.snmp") }}
              </cv-select-option>
            </cv-select>
          </div>

          <div class="form-grid-2 mg-top-md">
            <div>
              <cv-select
                v-if="tenants.length"
                v-model="form.customer"
                :label="$t('targets.customer_label')"
                :disabled="savingTarget"
                @change="onCustomerChange"
              >
                <cv-select-option
                  v-for="tenant in tenants"
                  :key="tenant.customer"
                  :value="tenant.customer"
                >
                  {{ tenant.display_name }} ({{ tenant.customer }})
                </cv-select-option>
              </cv-select>
              <NsTextInput
                v-else
                v-model.trim="form.customer"
                :label="$t('targets.customer_label')"
                placeholder="acme-corp"
                :disabled="savingTarget"
                :invalid-message="validationErrors.customer"
              />
            </div>

            <div>
              <cv-select
                v-if="availableSitesForCustomer.length"
                v-model="form.site"
                :label="$t('targets.site_label')"
                :disabled="savingTarget"
              >
                <cv-select-option
                  v-for="site in availableSitesForCustomer"
                  :key="site"
                  :value="site"
                >
                  {{ site }}
                </cv-select-option>
              </cv-select>
              <NsTextInput
                v-else
                v-model.trim="form.site"
                :label="$t('targets.site_label')"
                placeholder="hq"
                :disabled="savingTarget"
                :invalid-message="validationErrors.site"
              />
            </div>
          </div>

          <div class="form-grid-2 mg-top-md">
            <cv-select
              v-model="form.device_role"
              :label="$t('targets.device_role_label')"
              :disabled="savingTarget"
            >
              <cv-select-option
                v-for="role in deviceRoles"
                :key="role"
                :value="role"
              >
                {{ $t(`targets.roles.${role}`) }}
              </cv-select-option>
            </cv-select>

            <cv-select
              v-model="form.scrape_interval"
              :label="$t('targets.scrape_interval_label')"
              :disabled="savingTarget"
            >
              <cv-select-option
                v-for="interval in scrapeIntervals"
                :key="interval"
                :value="interval"
              >
                {{ interval }}
              </cv-select-option>
            </cv-select>
          </div>

          <NsToggle
            v-model="form.enabled"
            :label="$t('targets.target_enabled_label')"
            value="targetEnabled"
            :disabled="savingTarget"
            class="mg-top-md"
          >
            <template slot="text-left">{{ $t("common.disabled") }}</template>
            <template slot="text-right">{{ $t("common.enabled") }}</template>
          </NsToggle>

          <NsTextInput
            v-model="form.endpointsText"
            :label="$t('targets.endpoints_label')"
            :helper-text="endpointsHelperText"
            :placeholder="endpointsPlaceholder"
            :disabled="savingTarget"
            :invalid-message="validationErrors.endpoints"
          />

          <!-- Dynamic Section: NS8 Federation & Exporter -->
          <div
            v-if="
              form.target_type === 'ns8-federation' ||
              form.target_type === 'exporter'
            "
            class="form-section-divider"
          >
            <h3 class="form-section-title">
              {{ $t("targets.http_scrape_section") }}
            </h3>
            <div class="form-grid-2">
              <cv-select
                v-model="form.scheme"
                :label="$t('targets.scheme_label')"
                :disabled="savingTarget"
              >
                <cv-select-option value="https">HTTPS</cv-select-option>
                <cv-select-option value="http">HTTP</cv-select-option>
              </cv-select>

              <NsTextInput
                v-model.trim="form.metrics_path"
                :label="$t('targets.metrics_path_label')"
                placeholder="/metrics"
                :disabled="savingTarget"
                :invalid-message="validationErrors.metrics_path"
              />
            </div>

            <NsToggle
              v-model="form.tls_skip_verify"
              :label="$t('targets.tls_skip_verify_label')"
              value="tlsSkipVerify"
              :disabled="savingTarget"
            >
              <template slot="text-left">{{ $t("common.no") }}</template>
              <template slot="text-right">{{ $t("common.yes") }}</template>
            </NsToggle>

            <div class="form-grid-2">
              <NsTextInput
                v-model.trim="form.basic_auth_user"
                :label="$t('targets.basic_auth_user_label')"
                :disabled="savingTarget"
              />
              <NsTextInput
                v-model="form.basic_auth_password"
                type="password"
                :label="$t('targets.basic_auth_password_label')"
                :placeholder="
                  form.hasExistingSecret
                    ? $t('common.unchanged_placeholder')
                    : ''
                "
                :disabled="savingTarget"
              />
            </div>

            <NsTextInput
              v-model="form.bearer_token"
              type="password"
              :label="$t('targets.bearer_token_label')"
              :placeholder="
                form.hasExistingSecret ? $t('common.unchanged_placeholder') : ''
              "
              :disabled="savingTarget"
            />

            <NsTextInput
              v-if="form.target_type === 'ns8-federation'"
              v-model="form.matchSelectorsText"
              :label="$t('targets.match_selectors_label')"
              :helper-text="$t('targets.match_selectors_helper')"
              :disabled="savingTarget"
            />
          </div>

          <!-- Dynamic Section: Blackbox Probe -->
          <div
            v-if="form.target_type === 'blackbox'"
            class="form-section-divider"
          >
            <h3 class="form-section-title">
              {{ $t("targets.blackbox_section") }}
            </h3>
            <cv-select
              v-model="form.blackbox_module"
              :label="$t('targets.blackbox_module_label')"
              :disabled="savingTarget"
            >
              <cv-select-option
                v-for="mod in blackboxModules"
                :key="mod"
                :value="mod"
              >
                {{ $t(`targets.blackbox_modules.${mod}`) }}
              </cv-select-option>
            </cv-select>

            <NsToggle
              v-model="form.tls_skip_verify"
              :label="$t('targets.tls_skip_verify_label')"
              value="blackboxTlsSkipVerify"
              :disabled="savingTarget"
              class="mg-top-md"
            >
              <template slot="text-left">{{ $t("common.no") }}</template>
              <template slot="text-right">{{ $t("common.yes") }}</template>
            </NsToggle>
          </div>

          <!-- Dynamic Section: SNMP v2c / v3 -->
          <div
            v-if="form.target_type === 'snmp'"
            class="form-section-divider"
          >
            <h3 class="form-section-title">
              {{ $t("targets.snmp_section") }}
            </h3>
            <div class="form-grid-2">
              <cv-select
                v-model="form.snmp_module"
                :label="$t('targets.snmp_module_label')"
                :disabled="savingTarget"
                @change="onSnmpModuleChange"
              >
                <cv-select-option
                  v-for="mod in snmpModules"
                  :key="mod"
                  :value="mod"
                >
                  {{ $t(`targets.snmp_modules.${mod}`) }}
                </cv-select-option>
              </cv-select>

              <cv-select
                v-model="form.snmp_version"
                :label="$t('targets.snmp_version_label')"
                :disabled="savingTarget"
              >
                <cv-select-option value="v2c">SNMP v2c</cv-select-option>
                <cv-select-option value="v3">SNMP v3</cv-select-option>
              </cv-select>
            </div>

            <div v-if="form.snmp_version === 'v2c'" class="mg-top-md">
              <NsTextInput
                v-model="form.snmp_community"
                type="password"
                :label="$t('targets.snmp_community_label')"
                :placeholder="
                  form.hasExistingSecret
                    ? $t('common.unchanged_placeholder')
                    : 'public'
                "
                :disabled="savingTarget"
              />
            </div>

            <div v-else class="mg-top-md">
              <div class="form-grid-2">
                <NsTextInput
                  v-model.trim="form.snmp_v3.username"
                  :label="$t('targets.snmp_v3_username')"
                  :disabled="savingTarget"
                  :invalid-message="validationErrors.snmp_v3"
                />
                <cv-select
                  v-model="form.snmp_v3.security_level"
                  :label="$t('targets.snmp_v3_security_level')"
                  :disabled="savingTarget"
                >
                  <cv-select-option value="noAuthNoPriv">
                    noAuthNoPriv
                  </cv-select-option>
                  <cv-select-option value="authNoPriv">
                    authNoPriv
                  </cv-select-option>
                  <cv-select-option value="authPriv">
                    authPriv
                  </cv-select-option>
                </cv-select>
              </div>

              <div
                v-if="form.snmp_v3.security_level !== 'noAuthNoPriv'"
                class="form-grid-2 mg-top-md"
              >
                <cv-select
                  v-model="form.snmp_v3.auth_protocol"
                  :label="$t('targets.snmp_v3_auth_protocol')"
                  :disabled="savingTarget"
                >
                  <cv-select-option value="SHA256">SHA256</cv-select-option>
                  <cv-select-option value="SHA512">SHA512</cv-select-option>
                  <cv-select-option value="SHA384">SHA384</cv-select-option>
                  <cv-select-option value="SHA224">SHA224</cv-select-option>
                  <cv-select-option value="SHA">SHA</cv-select-option>
                  <cv-select-option value="MD5">MD5</cv-select-option>
                </cv-select>
                <NsTextInput
                  v-model="form.snmp_v3.auth_password"
                  type="password"
                  :label="$t('targets.snmp_v3_auth_password')"
                  :placeholder="
                    form.hasExistingSecret
                      ? $t('common.unchanged_placeholder')
                      : ''
                  "
                  :disabled="savingTarget"
                />
              </div>

              <div
                v-if="form.snmp_v3.security_level === 'authPriv'"
                class="form-grid-2 mg-top-md"
              >
                <cv-select
                  v-model="form.snmp_v3.priv_protocol"
                  :label="$t('targets.snmp_v3_priv_protocol')"
                  :disabled="savingTarget"
                >
                  <cv-select-option value="AES">AES</cv-select-option>
                  <cv-select-option value="AES192">AES192</cv-select-option>
                  <cv-select-option value="AES256">AES256</cv-select-option>
                  <cv-select-option value="DES">DES</cv-select-option>
                </cv-select>
                <NsTextInput
                  v-model="form.snmp_v3.priv_password"
                  type="password"
                  :label="$t('targets.snmp_v3_priv_password')"
                  :placeholder="
                    form.hasExistingSecret
                      ? $t('common.unchanged_placeholder')
                      : ''
                  "
                  :disabled="savingTarget"
                />
              </div>
            </div>
          </div>
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ isEditing ? $t("common.save") : $t("targets.create_target") }}
      </template>
    </NsModal>

    <!-- Delete Target Modal -->
    <NsModal
      kind="danger"
      size="small"
      :visible="showDeleteModal"
      :primary-button-disabled="deletingTarget"
      :isLoading="deletingTarget"
      @modal-hidden="showDeleteModal = false"
      @primary-click="submitDeleteTarget"
    >
      <template slot="title">{{ $t("targets.delete_modal_title") }}</template>
      <template slot="content">
        <p>
          {{
            $t("targets.delete_modal_desc", {
              name: targetToDelete ? targetToDelete.name : "",
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
import {
  TaskService,
  IconService,
  UtilService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import Add20 from "@carbon/icons-vue/es/add/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Edit16 from "@carbon/icons-vue/es/edit/16";
import TrashCan16 from "@carbon/icons-vue/es/trash-can/16";

const DEFAULT_FEDERATION_MATCH =
  '{__name__=~"node_.+|ns8_.+|up|restic_.+|systemd_.+"}';

export default {
  name: "Targets",
  mixins: [TaskService, IconService, UtilService, PageTitleService],
  pageTitle() {
    return `${this.$t("targets.title")} - ${this.appName}`;
  },
  data() {
    return {
      Add20,
      Renew20,
      Edit16,
      TrashCan16,
      loading: false,
      tableError: "",
      tenants: [],
      targets: [],
      tablePage: [],
      filters: {
        customer: "",
        target_type: "",
      },
      tableColumns: [
        "name",
        "target_type",
        "customer_site",
        "endpoints",
        "scrape_interval",
        "enabled",
        "actions",
      ],
      deviceRoles: [
        "ns8",
        "linux",
        "windows",
        "proxmox",
        "web",
        "snmp-network",
        "snmp-ups",
        "snmp-nas",
        "snmp-firewall",
        "snmp-printer",
      ],
      scrapeIntervals: ["10s", "15s", "30s", "60s", "120s", "300s"],
      blackboxModules: [
        "http_2xx",
        "http_post_2xx",
        "tcp_connect",
        "icmp",
        "dns_tcp",
        "dns_udp",
      ],
      snmpModules: [
        "if_mib",
        "apcupsd",
        "synology",
        "qnap",
        "mikrotik",
        "fortigate",
        "printer",
        "generic",
      ],
      feedbackBanner: {
        kind: "success",
        title: "",
        description: "",
      },
      showSaveModal: false,
      isEditing: false,
      savingTarget: false,
      validationErrors: {},
      form: this.createDefaultForm(),
      showDeleteModal: false,
      deletingTarget: false,
      targetToDelete: null,
    };
  },
  computed: {
    ...mapState(["instanceName", "appName", "core"]),
    i18nTableColumns() {
      return this.tableColumns.map((col) =>
        this.$t(`targets.columns.${col}`)
      );
    },
    availableSitesForCustomer() {
      const found = this.tenants.find(
        (t) => t.customer === this.form.customer
      );
      return found && Array.isArray(found.sites) ? found.sites : [];
    },
    endpointsPlaceholder() {
      if (this.form.target_type === "blackbox") {
        return "https://portal.acme.example.com, https://shop.acme.example.com";
      }
      if (this.form.target_type === "snmp") {
        return "10.20.0.1, 10.20.0.2";
      }
      return "node01.acme.example.com:9100";
    },
    endpointsHelperText() {
      return this.$t("targets.endpoints_helper");
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.loadTenantsLookup();
          this.loadTargets();
        }
      },
    },
  },
  methods: {
    createDefaultForm() {
      return {
        id: "",
        name: "",
        enabled: true,
        target_type: "blackbox",
        customer: "",
        site: "hq",
        device_role: "web",
        scrape_interval: "30s",
        endpointsText: "",
        scheme: "https",
        metrics_path: "/metrics",
        tls_skip_verify: false,
        basic_auth_user: "",
        basic_auth_password: "",
        bearer_token: "",
        hasExistingSecret: false,
        matchSelectorsText: DEFAULT_FEDERATION_MATCH,
        blackbox_module: "http_2xx",
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
    },
    clearFeedback() {
      this.feedbackBanner = { kind: "success", title: "", description: "" };
    },
    parseList(raw) {
      return Array.from(
        new Set(
          String(raw || "")
            .split(/[\n,]+/)
            .map((s) => s.trim())
            .filter(Boolean)
        )
      );
    },
    onTargetTypeChange() {
      if (this.form.target_type === "ns8-federation") {
        this.form.device_role = "ns8";
        this.form.metrics_path = "/federate";
      } else if (this.form.target_type === "blackbox") {
        this.form.device_role = "web";
      } else if (this.form.target_type === "snmp") {
        this.onSnmpModuleChange();
      } else {
        this.form.device_role = "linux";
        this.form.metrics_path = "/metrics";
      }
    },
    onSnmpModuleChange() {
      const roleMap = {
        if_mib: "snmp-network",
        mikrotik: "snmp-network",
        generic: "snmp-network",
        apcupsd: "snmp-ups",
        synology: "snmp-nas",
        qnap: "snmp-nas",
        fortigate: "snmp-firewall",
        printer: "snmp-printer",
      };
      this.form.device_role = roleMap[this.form.snmp_module] || "snmp-network";
    },
    onCustomerChange() {
      if (
        this.availableSitesForCustomer.length &&
        !this.availableSitesForCustomer.includes(this.form.site)
      ) {
        this.form.site = this.availableSitesForCustomer[0];
      }
    },
    async loadTenantsLookup() {
      const taskAction = "list-tenants";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(`${taskAction}-completed-${eventId}`, (ctx, res) => {
        const out = (res && res.output) || {};
        this.tenants = Array.isArray(out.tenants) ? out.tenants : [];
      });

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { search: "", page: 1, page_size: 200 },
          extra: {
            title: this.$t("action.list-tenants"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    async loadTargets() {
      this.loading = true;
      this.tableError = "";
      const taskAction = "list-targets";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.loadTargetsAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.loadTargetsCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            customer: this.filters.customer || "",
            target_type: this.filters.target_type || "",
            page: 1,
            page_size: 200,
          },
          extra: {
            title: this.$t("action.list-targets"),
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
    loadTargetsAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loading = false;
      this.tableError = this.$t("targets.cannot_load_targets");
      this.createErrorNotificationForApp(
        taskError,
        this.$t("targets.cannot_load_targets")
      );
    },
    loadTargetsCompleted(taskContext, taskResult) {
      this.loading = false;
      const out = (taskResult && taskResult.output) || {};
      this.targets = Array.isArray(out.targets) ? out.targets : [];
    },
    openCreateModal() {
      this.isEditing = false;
      this.validationErrors = {};
      const defaults = this.createDefaultForm();
      if (this.tenants.length) {
        defaults.customer = this.tenants[0].customer;
        defaults.site =
          Array.isArray(this.tenants[0].sites) && this.tenants[0].sites.length
            ? this.tenants[0].sites[0]
            : "hq";
      }
      this.form = defaults;
      this.showSaveModal = true;
    },
    openEditModal(row) {
      this.isEditing = true;
      this.validationErrors = {};
      const defaults = this.createDefaultForm();
      const rowV3 =
        row.snmp_v3 && typeof row.snmp_v3 === "object" ? row.snmp_v3 : {};
      const validAuthProtos = [
        "MD5",
        "SHA",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
      ];
      const validPrivProtos = ["DES", "AES", "AES192", "AES256"];
      this.form = Object.assign(defaults, {
        id: row.id || "",
        name: row.name || "",
        enabled: Boolean(row.enabled),
        target_type: row.target_type || "exporter",
        customer: row.customer || "",
        site: row.site || "hq",
        device_role: row.device_role || "linux",
        scrape_interval: row.scrape_interval || "30s",
        endpointsText: Array.isArray(row.endpoints)
          ? row.endpoints.join(", ")
          : "",
        scheme: row.scheme || "https",
        metrics_path: row.metrics_path || "/metrics",
        tls_skip_verify: Boolean(row.tls_skip_verify),
        basic_auth_user: row.basic_auth_user || "",
        basic_auth_password: "",
        bearer_token: "",
        hasExistingSecret: Boolean(row.has_secret),
        matchSelectorsText:
          Array.isArray(row.match_selectors) && row.match_selectors.length
            ? row.match_selectors.join("\n")
            : DEFAULT_FEDERATION_MATCH,
        blackbox_module: row.blackbox_module || "http_2xx",
        snmp_module: row.snmp_module || "if_mib",
        snmp_version: row.snmp_version || "v2c",
        snmp_community: row.has_secret ? "" : "public",
        snmp_v3: {
          username: rowV3.username || "",
          security_level: rowV3.security_level || "authPriv",
          auth_protocol: validAuthProtos.includes(rowV3.auth_protocol)
            ? rowV3.auth_protocol
            : "SHA256",
          auth_password: "",
          priv_protocol: validPrivProtos.includes(rowV3.priv_protocol)
            ? rowV3.priv_protocol
            : "AES",
          priv_password: "",
        },
      });
      this.showSaveModal = true;
    },
    validateTargetForm() {
      const errors = {};
      if (!this.form.name.trim()) {
        errors.name = this.$t("targets.validation_name");
      }
      if (!this.form.customer.trim()) {
        errors.customer = this.$t("targets.validation_customer");
      }
      if (!this.form.site.trim()) {
        errors.site = this.$t("targets.validation_site");
      }
      const endpoints = this.parseList(this.form.endpointsText);
      if (!endpoints.length) {
        errors.endpoints = this.$t("targets.validation_endpoints");
      }
      if (
        (this.form.target_type === "exporter" ||
          this.form.target_type === "ns8-federation") &&
        !/^\/[^\s]*$/.test(this.form.metrics_path)
      ) {
        errors.metrics_path = this.$t("targets.validation_metrics_path");
      }
      if (
        this.form.target_type === "snmp" &&
        this.form.snmp_version === "v3" &&
        !this.form.snmp_v3.username.trim()
      ) {
        errors.snmp_v3 = this.$t("targets.validation_snmp_v3_username");
      }
      this.validationErrors = errors;
      return Object.keys(errors).length === 0;
    },
    buildTargetPayload() {
      const endpoints = this.parseList(this.form.endpointsText);
      const matchSelectors = String(this.form.matchSelectorsText || "")
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length >= 3);

      const newSecretEntered = Boolean(
        this.form.basic_auth_password ||
          this.form.bearer_token ||
          (this.form.target_type === "snmp" &&
            this.form.snmp_version === "v2c" &&
            this.form.snmp_community) ||
          (this.form.target_type === "snmp" &&
            this.form.snmp_version === "v3" &&
            (this.form.snmp_v3.auth_password ||
              this.form.snmp_v3.priv_password))
      );

      const payload = {
        id: this.isEditing ? this.form.id : "",
        name: this.form.name.trim(),
        enabled: Boolean(this.form.enabled),
        target_type: this.form.target_type,
        customer: this.form.customer.trim().toLowerCase(),
        site: this.form.site.trim().toLowerCase(),
        device_role: this.form.device_role,
        scrape_interval: this.form.scrape_interval,
        endpoints,
        scheme: this.form.scheme,
        metrics_path: this.form.metrics_path || "/metrics",
        tls_skip_verify: Boolean(this.form.tls_skip_verify),
        basic_auth_user: (this.form.basic_auth_user || "").trim(),
        basic_auth_password: this.form.basic_auth_password || "",
        bearer_token: this.form.bearer_token || "",
        secret_unchanged: Boolean(
          this.isEditing && this.form.hasExistingSecret && !newSecretEntered
        ),
        match_selectors: matchSelectors.length
          ? matchSelectors
          : [DEFAULT_FEDERATION_MATCH],
        blackbox_module: this.form.blackbox_module,
        snmp_module: this.form.snmp_module,
        snmp_version: this.form.snmp_version,
        snmp_community: this.form.snmp_community || "",
      };

      if (this.form.target_type === "snmp" && this.form.snmp_version === "v3") {
        payload.snmp_v3 = {
          username: this.form.snmp_v3.username.trim(),
          security_level: this.form.snmp_v3.security_level,
          auth_protocol: this.form.snmp_v3.auth_protocol,
          auth_password: this.form.snmp_v3.auth_password || "",
          priv_protocol: this.form.snmp_v3.priv_protocol,
          priv_password: this.form.snmp_v3.priv_password || "",
        };
      }

      return payload;
    },
    async submitSaveTarget() {
      if (!this.validateTargetForm()) {
        return;
      }
      this.savingTarget = true;
      const payload = this.buildTargetPayload();
      const taskAction = "save-target";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.saveTargetAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.saveTargetValidationFailed
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.saveTargetCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.save-target"),
            description: payload.name,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.savingTarget = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    saveTargetAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.savingTarget = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("targets.save_failed")
      );
    },
    saveTargetValidationFailed(validationErrors) {
      this.savingTarget = false;
      const mapped = {};
      const errList = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];
      errList.forEach((item) => {
        const key = item.field || item.parameter || "endpoints";
        mapped[key] = this.$te(`validation.${item.error}`)
          ? this.$t(`validation.${item.error}`)
          : item.error;
      });
      this.validationErrors = mapped;
    },
    saveTargetCompleted() {
      this.savingTarget = false;
      this.showSaveModal = false;
      this.feedbackBanner = {
        kind: "success",
        title: this.$t("targets.saved_title"),
        description: this.$t("targets.saved_description", {
          name: this.form.name,
        }),
      };
      this.loadTargets();
    },
    openDeleteModal(row) {
      this.targetToDelete = row;
      this.showDeleteModal = true;
    },
    async submitDeleteTarget() {
      if (!this.targetToDelete) {
        return;
      }
      this.deletingTarget = true;
      const taskAction = "delete-target";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.deleteTargetAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.deleteTargetCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            id: this.targetToDelete.id,
          },
          extra: {
            title: this.$t("action.delete-target"),
            description: this.targetToDelete.name,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.deletingTarget = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    deleteTargetAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.deletingTarget = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("targets.delete_failed")
      );
    },
    deleteTargetCompleted() {
      this.deletingTarget = false;
      this.showDeleteModal = false;
      this.feedbackBanner = {
        kind: "info",
        title: this.$t("targets.deleted_title"),
        description: this.$t("targets.deleted_description", {
          name: this.targetToDelete ? this.targetToDelete.name : "",
        }),
      };
      this.targetToDelete = null;
      this.loadTargets();
    },
  },
};
</script>
