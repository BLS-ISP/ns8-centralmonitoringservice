<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("tenants.title") }}</h1>
      <div class="page-toolbar__actions">
        <NsButton
          kind="secondary"
          size="field"
          :icon="Renew20"
          :disabled="loading"
          @click="loadTenants"
        >
          {{ $t("common.refresh") }}
        </NsButton>
        <NsButton
          kind="primary"
          size="field"
          :icon="Add20"
          @click="openCreateModal"
        >
          {{ $t("tenants.create_tenant") }}
        </NsButton>
      </div>
    </div>

    <!-- One-Time Newly Minted / Rotated Token Banner -->
    <div
      v-if="revealedToken.auth_token"
      class="token-secret-box"
      role="alert"
    >
      <div class="page-toolbar mg-bottom-sm">
        <div>
          <strong>
            {{
              $t("tenants.one_time_token_title", {
                customer: revealedToken.customer,
              })
            }}
          </strong>
          <div class="form-section-desc">
            {{ $t("tenants.one_time_token_warning") }}
            <span v-if="revealedToken.previous_token_expires_at">
              {{
                $t("tenants.previous_token_grace_until", {
                  expires: revealedToken.previous_token_expires_at,
                })
              }}
            </span>
          </div>
        </div>
        <NsButton
          kind="ghost"
          size="sm"
          @click="dismissRevealedToken"
        >
          {{ $t("common.dismiss") }}
        </NsButton>
      </div>
      <div class="token-secret-box__code">
        <span>{{ revealedToken.auth_token }}</span>
        <NsButton
          kind="primary"
          size="sm"
          :icon="Copy16"
          @click="copySecret(revealedToken.auth_token)"
        >
          {{
            tokenCopied
              ? $t("common.copied")
              : $t("tenants.copy_bearer_token")
          }}
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

    <!-- Tenants DataTable -->
    <section class="section-card">
      <NsDataTable
        :allRows="tenants"
        :columns="i18nTableColumns"
        :rawColumns="tableColumns"
        :isSearchable="true"
        :searchPlaceholder="$t('tenants.search_placeholder')"
        :searchClearLabel="$t('common.clear_search')"
        :noSearchResultsLabel="$t('common.no_results')"
        :noSearchResultsDescription="$t('common.try_changing_search')"
        :isLoading="loading"
        :skeletonRows="5"
        :isErrorShown="!!tableError"
        :errorTitle="$t('tenants.cannot_load_tenants')"
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
          <NsEmptyState :title="$t('tenants.empty_title')">
            <template #description>
              <div>{{ $t("tenants.empty_description") }}</div>
              <NsButton
                kind="primary"
                size="field"
                :icon="Add20"
                class="mg-top-md"
                @click="openCreateModal"
              >
                {{ $t("tenants.create_tenant") }}
              </NsButton>
            </template>
          </NsEmptyState>
        </template>

        <template slot="data">
          <cv-data-table-row
            v-for="(row, rowIndex) in tablePage"
            :key="row.customer || `${rowIndex}`"
            :value="row.customer || `${rowIndex}`"
          >
            <cv-data-table-cell>
              <div>
                <strong>{{ row.display_name }}</strong>
              </div>
              <div class="mono-text">{{ row.customer }}</div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <div class="tag-list">
                <NsTag
                  v-for="site in row.sites"
                  :key="site"
                  kind="gray"
                  :label="site"
                />
              </div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <NsTag
                :kind="row.customer_portal_enabled ? 'green' : 'gray'"
                :label="
                  row.customer_portal_enabled
                    ? $t('tenants.portal_enabled_badge', {
                        user: row.portal_viewer_username,
                      })
                    : $t('tenants.portal_disabled_badge')
                "
              />
            </cv-data-table-cell>

            <cv-data-table-cell>
              <span class="mono-text">{{ row.token_prefix }}</span>
              <div
                v-if="row.previous_token_expires_at"
                class="form-section-desc"
              >
                {{ $t("tenants.grace_active") }}
              </div>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <span>{{ row.last_ingest_at || $t("tenants.never_ingested") }}</span>
            </cv-data-table-cell>

            <cv-data-table-cell>
              <div class="table-row-actions">
                <NsButton
                  kind="secondary"
                  size="sm"
                  :icon="Terminal20"
                  @click="openBundleModal(row)"
                >
                  {{ $t("tenants.agent_bundle_btn") }}
                </NsButton>
                <NsButton
                  kind="ghost"
                  size="sm"
                  :icon="Renew20"
                  @click="openRotateModal(row)"
                >
                  {{ $t("tenants.rotate_token_btn") }}
                </NsButton>
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

    <!-- Create / Edit Tenant Modal -->
    <NsModal
      size="default"
      :visible="showSaveModal"
      :primary-button-disabled="savingTenant"
      :isLoading="savingTenant"
      @modal-hidden="closeSaveModal"
      @primary-click="submitSaveTenant"
    >
      <template slot="title">
        {{
          isEditing
            ? $t("tenants.edit_tenant_title", { customer: form.customer })
            : $t("tenants.create_tenant")
        }}
      </template>
      <template slot="content">
        <cv-form @submit.prevent="submitSaveTenant">
          <div class="form-grid-2">
            <NsTextInput
              v-model.trim="form.customer"
              :label="$t('tenants.customer_slug_label')"
              :helper-text="$t('tenants.customer_slug_helper')"
              placeholder="acme-corp"
              :disabled="isEditing || savingTenant"
              :invalid-message="validationErrors.customer"
              ref="customerInput"
            />
            <NsTextInput
              v-model.trim="form.display_name"
              :label="$t('tenants.display_name_label')"
              placeholder="ACME Corporation GmbH"
              :disabled="savingTenant"
              :invalid-message="validationErrors.display_name"
            />
          </div>

          <NsTextInput
            v-model="form.sitesText"
            :label="$t('tenants.sites_label')"
            :helper-text="$t('tenants.sites_helper')"
            placeholder="hq, dc1, branch-berlin"
            :disabled="savingTenant"
            :invalid-message="validationErrors.sites"
          />

          <NsTextInput
            v-model="form.contactEmailsText"
            :label="$t('tenants.contact_emails_label')"
            :helper-text="$t('tenants.contact_emails_helper')"
            placeholder="it-alerts@acme.example.com, noc@acme.example.com"
            :disabled="savingTenant"
            :invalid-message="validationErrors.contact_emails"
          />

          <div class="form-section-divider">
            <h3 class="form-section-title">
              {{ $t("tenants.portal_section_title") }}
            </h3>
            <p class="form-section-desc">
              {{ $t("tenants.portal_section_desc") }}
            </p>

            <NsToggle
              v-model="form.customer_portal_enabled"
              :label="$t('tenants.enable_customer_portal')"
              value="portalEnabled"
              :disabled="savingTenant"
            >
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <div v-if="form.customer_portal_enabled" class="form-grid-2">
              <NsTextInput
                v-model.trim="form.portal_viewer_username"
                :label="$t('tenants.portal_viewer_username')"
                placeholder="acme-viewer"
                :disabled="savingTenant"
                :invalid-message="validationErrors.portal_viewer_username"
              />
              <NsTextInput
                v-model="form.portal_viewer_password"
                type="password"
                :label="$t('tenants.portal_viewer_password')"
                :helper-text="
                  isEditing
                    ? $t('tenants.portal_password_keep_helper')
                    : $t('tenants.portal_password_min_helper')
                "
                :placeholder="
                  isEditing
                    ? $t('common.unchanged_placeholder')
                    : $t('tenants.portal_password_placeholder')
                "
                :disabled="savingTenant"
                :invalid-message="validationErrors.portal_viewer_password"
              />
            </div>
          </div>

          <NsTextInput
            v-model="form.notes"
            :label="$t('tenants.notes_label')"
            :placeholder="$t('tenants.notes_placeholder')"
            :disabled="savingTenant"
            :invalid-message="validationErrors.notes"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ isEditing ? $t("common.save") : $t("tenants.create_tenant") }}
      </template>
    </NsModal>

    <!-- Rotate Bearer Token Modal -->
    <NsModal
      size="small"
      :visible="showRotateModal"
      :primary-button-disabled="rotatingToken"
      :isLoading="rotatingToken"
      @modal-hidden="showRotateModal = false"
      @primary-click="submitRotateToken"
    >
      <template slot="title">
        {{
          $t("tenants.rotate_modal_title", {
            customer: rotateForm.customer,
          })
        }}
      </template>
      <template slot="content">
        <p class="mg-bottom-md">{{ $t("tenants.rotate_modal_desc") }}</p>
        <NsTextInput
          v-model="rotateForm.grace_period_minutes"
          type="number"
          :label="$t('tenants.grace_period_minutes_label')"
          :helper-text="$t('tenants.grace_period_minutes_helper')"
          :disabled="rotatingToken"
          :invalid-message="rotateValidationError"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("tenants.rotate_token_btn") }}
      </template>
    </NsModal>

    <!-- Delete Tenant Modal -->
    <NsModal
      kind="danger"
      size="small"
      :visible="showDeleteModal"
      :primary-button-disabled="
        deletingTenant || deleteForm.confirmText !== deleteForm.customer
      "
      :isLoading="deletingTenant"
      @modal-hidden="showDeleteModal = false"
      @primary-click="submitDeleteTenant"
    >
      <template slot="title">
        {{
          $t("tenants.delete_modal_title", {
            customer: deleteForm.customer,
          })
        }}
      </template>
      <template slot="content">
        <p class="mg-bottom-md">
          {{
            $t("tenants.delete_modal_desc", {
              customer: deleteForm.customer,
            })
          }}
        </p>
        <NsCheckbox
          v-model="deleteForm.delete_central_targets"
          :label="$t('tenants.delete_central_targets_label')"
          value="deleteCentralTargets"
          class="mg-bottom-md"
        />
        <NsTextInput
          v-model.trim="deleteForm.confirmText"
          :label="
            $t('tenants.type_slug_to_confirm', {
              customer: deleteForm.customer,
            })
          "
          :placeholder="deleteForm.customer"
          :disabled="deletingTenant"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("common.delete") }}</template>
    </NsModal>

    <!-- 1-Click Standalone Alloy Onboarding Bundle Modal -->
    <NsModal
      size="large"
      :visible="showBundleModal"
      :primary-button-disabled="generatingBundle"
      :isLoading="generatingBundle"
      @modal-hidden="showBundleModal = false"
      @primary-click="submitGenerateBundle"
    >
      <template slot="title">
        {{
          $t("tenants.bundle_modal_title", {
            customer: bundleForm.customer,
          })
        }}
      </template>
      <template slot="content">
        <p class="form-section-desc">
          {{ $t("tenants.bundle_modal_subtitle") }}
        </p>

        <div class="form-grid-2">
          <cv-select
            v-model="bundleForm.platform"
            :label="$t('tenants.bundle_platform_label')"
            :disabled="generatingBundle"
          >
            <cv-select-option value="linux">
              {{ $t("tenants.platform_linux") }}
            </cv-select-option>
            <cv-select-option value="windows">
              {{ $t("tenants.platform_windows") }}
            </cv-select-option>
            <cv-select-option value="docker">
              {{ $t("tenants.platform_docker") }}
            </cv-select-option>
          </cv-select>

          <cv-select
            v-model="bundleForm.site"
            :label="$t('tenants.bundle_site_label')"
            :disabled="generatingBundle"
          >
            <cv-select-option
              v-for="site in bundleForm.availableSites"
              :key="site"
              :value="site"
            >
              {{ site }}
            </cv-select-option>
          </cv-select>
        </div>

        <div class="form-grid-2 mg-top-md">
          <NsTextInput
            v-model.trim="bundleForm.collector_id"
            :label="$t('tenants.bundle_collector_id_label')"
            :helper-text="$t('tenants.bundle_collector_id_helper')"
            :placeholder="`${bundleForm.customer}-${bundleForm.site}-${bundleForm.platform}`"
            :disabled="generatingBundle"
            :invalid-message="bundleErrors.collector_id"
          />

          <NsTextInput
            v-model="bundleForm.syslog_port"
            type="number"
            :label="$t('tenants.bundle_syslog_port_label')"
            :helper-text="$t('tenants.bundle_syslog_port_helper')"
            :disabled="generatingBundle"
            :invalid-message="bundleErrors.syslog_port"
          />
        </div>

        <NsToggle
          v-model="bundleForm.issue_dedicated_token"
          :label="$t('tenants.bundle_dedicated_token_label')"
          value="issueDedicatedToken"
          :disabled="generatingBundle"
        >
          <template slot="text-left">{{ $t("common.no") }}</template>
          <template slot="text-right">{{ $t("common.yes") }}</template>
        </NsToggle>

        <!-- Rendered Bundle Output -->
        <div v-if="generatedBundle" class="form-section-divider">
          <NsInlineNotification
            kind="info"
            :title="
              $t('tenants.bundle_ready_title', {
                collector: generatedBundle.collector_id,
                prefix: generatedBundle.token_prefix,
              })
            "
            :description="generatedBundle.instructions"
            :showCloseButton="false"
            class="mg-bottom-md"
          />

          <div class="bundle-file-header">
            <strong class="mono-text">
              {{ generatedBundle.installer_filename }}
            </strong>
            <div class="table-row-actions">
              <NsButton
                kind="ghost"
                size="sm"
                :icon="Copy16"
                @click="copySecret(generatedBundle.installer_content)"
              >
                {{ $t("common.copy") }}
              </NsButton>
              <NsButton
                kind="secondary"
                size="sm"
                :icon="Download16"
                @click="
                  downloadTextFile(
                    generatedBundle.installer_filename,
                    generatedBundle.installer_content
                  )
                "
              >
                {{ $t("common.download") }}
              </NsButton>
            </div>
          </div>
          <NsCodeSnippet
            :copyTooltip="$t('common.copy')"
            :copyFeedback="$t('common.copied')"
            :moreText="$t('common.show_more')"
            :lessText="$t('common.show_less')"
          >{{ generatedBundle.installer_content }}</NsCodeSnippet>

          <div class="bundle-file-header">
            <strong class="mono-text">
              {{ generatedBundle.config_filename }}
            </strong>
            <div class="table-row-actions">
              <NsButton
                kind="ghost"
                size="sm"
                :icon="Copy16"
                @click="copySecret(generatedBundle.config_content)"
              >
                {{ $t("common.copy") }}
              </NsButton>
              <NsButton
                kind="secondary"
                size="sm"
                :icon="Download16"
                @click="
                  downloadTextFile(
                    generatedBundle.config_filename,
                    generatedBundle.config_content
                  )
                "
              >
                {{ $t("common.download") }}
              </NsButton>
            </div>
          </div>
          <NsCodeSnippet
            :copyTooltip="$t('common.copy')"
            :copyFeedback="$t('common.copied')"
            :moreText="$t('common.show_more')"
            :lessText="$t('common.show_less')"
          >{{ generatedBundle.config_content }}</NsCodeSnippet>
        </div>
      </template>
      <template slot="secondary-button">{{ $t("common.close") }}</template>
      <template slot="primary-button">
        {{ $t("tenants.generate_bundle_action") }}
      </template>
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
import Terminal20 from "@carbon/icons-vue/es/terminal/20";
import Copy16 from "@carbon/icons-vue/es/copy/16";
import Download16 from "@carbon/icons-vue/es/download/16";

const CUSTOMER_SLUG_RE = /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/;
const SITE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PORTAL_USER_RE = /^[a-zA-Z0-9._@-]{3,64}$/;
const COLLECTOR_ID_RE = /^([a-z0-9][a-z0-9._-]{1,62}[a-z0-9])?$/;

export default {
  name: "Tenants",
  mixins: [TaskService, IconService, UtilService, PageTitleService],
  pageTitle() {
    return `${this.$t("tenants.title")} - ${this.appName}`;
  },
  data() {
    return {
      Add20,
      Renew20,
      Edit16,
      TrashCan16,
      Terminal20,
      Copy16,
      Download16,
      loading: false,
      tableError: "",
      tenants: [],
      tablePage: [],
      tableColumns: [
        "display_name",
        "sites",
        "customer_portal_enabled",
        "token_prefix",
        "last_ingest_at",
        "actions",
      ],
      feedbackBanner: {
        kind: "success",
        title: "",
        description: "",
      },
      revealedToken: {
        customer: "",
        auth_token: "",
        previous_token_expires_at: null,
      },
      tokenCopied: false,
      showSaveModal: false,
      isEditing: false,
      savingTenant: false,
      validationErrors: {},
      form: {
        customer: "",
        display_name: "",
        sitesText: "hq",
        contactEmailsText: "",
        customer_portal_enabled: false,
        portal_viewer_username: "",
        portal_viewer_password: "",
        notes: "",
      },
      showRotateModal: false,
      rotatingToken: false,
      rotateValidationError: "",
      rotateForm: {
        customer: "",
        grace_period_minutes: "60",
      },
      showDeleteModal: false,
      deletingTenant: false,
      deleteForm: {
        customer: "",
        delete_central_targets: true,
        confirmText: "",
      },
      showBundleModal: false,
      generatingBundle: false,
      bundleErrors: {},
      bundleForm: {
        customer: "",
        availableSites: [],
        site: "",
        platform: "linux",
        collector_id: "",
        issue_dedicated_token: true,
        syslog_port: "5514",
      },
      generatedBundle: null,
    };
  },
  computed: {
    ...mapState(["instanceName", "appName", "core"]),
    i18nTableColumns() {
      return this.tableColumns.map((col) =>
        this.$t(`tenants.columns.${col}`)
      );
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.loadTenants();
        }
      },
    },
  },
  methods: {
    clearFeedback() {
      this.feedbackBanner = { kind: "success", title: "", description: "" };
    },
    dismissRevealedToken() {
      this.revealedToken = {
        customer: "",
        auth_token: "",
        previous_token_expires_at: null,
      };
      this.tokenCopied = false;
    },
    async copySecret(text) {
      if (!text) {
        return;
      }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        }
      } catch (e) {
        // Clipboard permission fallback ignored
      }
      this.tokenCopied = true;
    },
    downloadTextFile(filename, content) {
      const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    },
    async loadTenants() {
      this.loading = true;
      this.tableError = "";
      const taskAction = "list-tenants";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.loadTenantsAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.loadTenantsCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            search: "",
            page: 1,
            page_size: 200,
          },
          extra: {
            title: this.$t("action.list-tenants"),
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
    loadTenantsAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loading = false;
      this.tableError = this.$t("tenants.cannot_load_tenants");
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.cannot_load_tenants")
      );
    },
    loadTenantsCompleted(taskContext, taskResult) {
      this.loading = false;
      const out = (taskResult && taskResult.output) || {};
      this.tenants = Array.isArray(out.tenants) ? out.tenants : [];
    },
    openCreateModal() {
      this.isEditing = false;
      this.validationErrors = {};
      this.form = {
        customer: "",
        display_name: "",
        sitesText: "hq",
        contactEmailsText: "",
        customer_portal_enabled: false,
        portal_viewer_username: "",
        portal_viewer_password: "",
        notes: "",
      };
      this.showSaveModal = true;
    },
    openEditModal(row) {
      this.isEditing = true;
      this.validationErrors = {};
      this.form = {
        customer: row.customer,
        display_name: row.display_name || "",
        sitesText: Array.isArray(row.sites) ? row.sites.join(", ") : "hq",
        contactEmailsText: Array.isArray(row.contact_emails)
          ? row.contact_emails.join(", ")
          : "",
        customer_portal_enabled: Boolean(row.customer_portal_enabled),
        portal_viewer_username: row.portal_viewer_username || "",
        portal_viewer_password: "",
        notes: row.notes || "",
      };
      this.showSaveModal = true;
    },
    closeSaveModal() {
      this.showSaveModal = false;
    },
    parseList(raw) {
      return Array.from(
        new Set(
          String(raw || "")
            .split(/[\n,;]+/)
            .map((item) => item.trim())
            .filter(Boolean)
        )
      );
    },
    validateSaveTenant() {
      const errors = {};
      const customer = this.form.customer.trim().toLowerCase();
      if (!CUSTOMER_SLUG_RE.test(customer)) {
        errors.customer = this.$t("tenants.validation_customer_slug");
      }
      if (!this.form.display_name.trim()) {
        errors.display_name = this.$t("tenants.validation_display_name");
      }
      const sites = this.parseList(this.form.sitesText).map((s) =>
        s.toLowerCase()
      );
      if (!sites.length || sites.some((s) => !SITE_SLUG_RE.test(s))) {
        errors.sites = this.$t("tenants.validation_sites");
      }
      const emails = this.parseList(this.form.contactEmailsText);
      if (emails.some((em) => !EMAIL_RE.test(em))) {
        errors.contact_emails = this.$t("tenants.validation_emails");
      }
      if (this.form.customer_portal_enabled) {
        if (!PORTAL_USER_RE.test(this.form.portal_viewer_username.trim())) {
          errors.portal_viewer_username = this.$t(
            "tenants.validation_portal_username"
          );
        }
        if (
          !this.isEditing &&
          this.form.portal_viewer_password.length < 10
        ) {
          errors.portal_viewer_password = this.$t(
            "tenants.validation_portal_password"
          );
        }
      }
      if (
        this.form.portal_viewer_password.length > 0 &&
        this.form.portal_viewer_password.length < 10
      ) {
        errors.portal_viewer_password = this.$t(
          "tenants.validation_portal_password"
        );
      }

      this.validationErrors = errors;
      return Object.keys(errors).length === 0;
    },
    async submitSaveTenant() {
      if (!this.validateSaveTenant()) {
        return;
      }
      this.savingTenant = true;
      const sites = this.parseList(this.form.sitesText).map((s) =>
        s.toLowerCase()
      );
      const contact_emails = this.parseList(this.form.contactEmailsText);
      const payload = {
        customer: this.form.customer.trim().toLowerCase(),
        display_name: this.form.display_name.trim(),
        sites,
        contact_emails,
        customer_portal_enabled: Boolean(this.form.customer_portal_enabled),
        portal_viewer_username: this.form.customer_portal_enabled
          ? this.form.portal_viewer_username.trim()
          : "",
        portal_viewer_password: this.form.portal_viewer_password || "",
        notes: (this.form.notes || "").trim(),
      };

      const taskAction = "save-tenant";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.saveTenantAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.saveTenantValidationFailed
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.saveTenantCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.save-tenant"),
            description: payload.display_name,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.savingTenant = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    saveTenantAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.savingTenant = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.save_failed")
      );
    },
    saveTenantValidationFailed(validationErrors) {
      this.savingTenant = false;
      const mapped = {};
      const errList = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];
      errList.forEach((item) => {
        const key = item.field || item.parameter;
        if (key) {
          mapped[key] = this.$te(`validation.${item.error}`)
            ? this.$t(`validation.${item.error}`)
            : item.error;
        }
      });
      this.validationErrors = mapped;
    },
    saveTenantCompleted(taskContext, taskResult) {
      this.savingTenant = false;
      this.showSaveModal = false;
      const out = (taskResult && taskResult.output) || {};
      if (out.auth_token) {
        this.revealedToken = {
          customer: out.customer,
          auth_token: out.auth_token,
          previous_token_expires_at: null,
        };
        this.tokenCopied = false;
      } else {
        this.feedbackBanner = {
          kind: "success",
          title: this.$t("tenants.saved_title"),
          description: this.$t("tenants.saved_description", {
            customer: out.customer || this.form.customer,
          }),
        };
      }
      this.loadTenants();
    },
    openRotateModal(row) {
      this.rotateValidationError = "";
      this.rotateForm = {
        customer: row.customer,
        grace_period_minutes: "60",
      };
      this.showRotateModal = true;
    },
    async submitRotateToken() {
      const grace = parseInt(this.rotateForm.grace_period_minutes, 10);
      if (isNaN(grace) || grace < 0 || grace > 10080) {
        this.rotateValidationError = this.$t(
          "tenants.validation_grace_minutes"
        );
        return;
      }
      this.rotatingToken = true;
      const payload = {
        customer: this.rotateForm.customer,
        grace_period_minutes: grace,
      };
      const taskAction = "rotate-token";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.rotateTokenAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.rotateTokenCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.rotate-token"),
            description: payload.customer,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.rotatingToken = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    rotateTokenAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.rotatingToken = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.rotate_failed")
      );
    },
    rotateTokenCompleted(taskContext, taskResult) {
      this.rotatingToken = false;
      this.showRotateModal = false;
      const out = (taskResult && taskResult.output) || {};
      this.revealedToken = {
        customer: out.customer || this.rotateForm.customer,
        auth_token: out.auth_token || "",
        previous_token_expires_at: out.previous_token_expires_at || null,
      };
      this.tokenCopied = false;
      this.loadTenants();
    },
    openDeleteModal(row) {
      this.deleteForm = {
        customer: row.customer,
        delete_central_targets: true,
        confirmText: "",
      };
      this.showDeleteModal = true;
    },
    async submitDeleteTenant() {
      if (this.deleteForm.confirmText !== this.deleteForm.customer) {
        return;
      }
      this.deletingTenant = true;
      const payload = {
        customer: this.deleteForm.customer,
        delete_central_targets: Boolean(
          this.deleteForm.delete_central_targets
        ),
      };
      const taskAction = "delete-tenant";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.deleteTenantAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.deleteTenantCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.delete-tenant"),
            description: payload.customer,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.deletingTenant = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    deleteTenantAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.deletingTenant = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.delete_failed")
      );
    },
    deleteTenantCompleted(taskContext, taskResult) {
      this.deletingTenant = false;
      this.showDeleteModal = false;
      const out = (taskResult && taskResult.output) || {};
      this.feedbackBanner = {
        kind: "info",
        title: this.$t("tenants.deleted_title"),
        description: this.$t("tenants.deleted_description", {
          customer: out.customer || this.deleteForm.customer,
        }),
      };
      this.loadTenants();
    },
    openBundleModal(row) {
      const sites =
        Array.isArray(row.sites) && row.sites.length ? row.sites : ["hq"];
      this.bundleErrors = {};
      this.generatedBundle = null;
      this.bundleForm = {
        customer: row.customer,
        availableSites: sites,
        site: sites[0],
        platform: "linux",
        collector_id: "",
        issue_dedicated_token: true,
        syslog_port: "5514",
      };
      this.showBundleModal = true;
    },
    async submitGenerateBundle() {
      const errors = {};
      const collectorId = (this.bundleForm.collector_id || "").trim();
      if (!COLLECTOR_ID_RE.test(collectorId)) {
        errors.collector_id = this.$t("tenants.validation_collector_id");
      }
      const syslogPort = parseInt(this.bundleForm.syslog_port, 10);
      if (isNaN(syslogPort) || syslogPort < 1024 || syslogPort > 65535) {
        errors.syslog_port = this.$t("tenants.validation_syslog_port");
      }
      this.bundleErrors = errors;
      if (Object.keys(errors).length > 0) {
        return;
      }

      this.generatingBundle = true;
      const payload = {
        customer: this.bundleForm.customer,
        site: this.bundleForm.site,
        platform: this.bundleForm.platform,
        collector_id: collectorId,
        issue_dedicated_token: Boolean(this.bundleForm.issue_dedicated_token),
        syslog_port: syslogPort,
      };
      const taskAction = "generate-agent-bundle";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.generateBundleAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.generateBundleCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.generate-agent-bundle"),
            description: `${payload.customer} (${payload.platform})`,
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.generatingBundle = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    generateBundleAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.generatingBundle = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.bundle_failed")
      );
    },
    generateBundleCompleted(taskContext, taskResult) {
      this.generatingBundle = false;
      this.generatedBundle = (taskResult && taskResult.output) || null;
    },
  },
};
</script>
