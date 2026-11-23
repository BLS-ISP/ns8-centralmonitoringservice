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

    <!-- Customer Portal Login Explanation & Central Login URL Bar -->
    <div class="portal-info-bar">
      <div class="portal-info-bar__header">
        <div class="portal-info-bar__title">
          {{ $t("tenants.portal_info_title") }}
        </div>
        <div v-if="effectiveGrafanaLoginUrl" class="table-row-actions">
          <NsButton
            kind="ghost"
            size="sm"
            :icon="Copy16"
            @click="copyWithFeedback(effectiveGrafanaLoginUrl)"
          >
            {{ $t("common.copy") }}
          </NsButton>
          <NsButton
            kind="secondary"
            size="sm"
            :icon="Launch20"
            @click="openExternalUrl(effectiveGrafanaLoginUrl)"
          >
            {{ $t("tenants.open_login_page") }}
          </NsButton>
        </div>
      </div>
      <div class="portal-info-bar__desc">
        {{ $t("tenants.portal_info_desc") }}
      </div>
      <div v-if="effectiveGrafanaLoginUrl" class="mono-text">
        <strong>{{ $t("tenants.portal_login_url_label") }}:</strong>
        {{ effectiveGrafanaLoginUrl }}
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
                    ? $t('tenants.portal_enabled_accounts_badge', {
                        count:
                          row.portal_users_count !== undefined
                            ? row.portal_users_count
                            : row.portal_viewer_username
                            ? 1
                            : 0,
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
                  :icon="UserMultiple20"
                  @click="openPortalUsersModal(row)"
                >
                  {{ $t("tenants.portal_users_btn") }}
                </NsButton>
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

    <!-- Multi-User Customer Grafana Account Management Modal -->
    <NsModal
      size="large"
      :visible="showPortalUsersModal"
      :primary-button-disabled="savingPortalUser || loadingPortalUsers"
      :isLoading="savingPortalUser"
      @modal-hidden="closePortalUsersModal"
      @primary-click="submitSavePortalUser"
    >
      <template slot="title">
        {{
          $t("tenants.portal_users_modal_title", {
            customer: portalModal.display_name || portalModal.customer,
          })
        }}
      </template>
      <template slot="content">
        <!-- Organization & Login URL Summary -->
        <div class="endpoint-row mg-bottom-md">
          <div>
            <div>
              <strong>{{ $t("tenants.portal_users_org_label") }}:</strong>
              {{
                portalModal.grafana_org_name ||
                `Customer: ${portalModal.display_name || portalModal.customer} (${portalModal.customer})`
              }}
            </div>
            <div v-if="portalModalLoginUrl">
              <strong>{{ $t("tenants.portal_login_url_label") }}:</strong>
              {{ portalModalLoginUrl }}
            </div>
          </div>
          <div v-if="portalModalLoginUrl" class="table-row-actions">
            <NsButton
              kind="ghost"
              size="sm"
              :icon="Copy16"
              @click="copySecret(portalModalLoginUrl)"
            >
              {{ $t("common.copy") }}
            </NsButton>
            <NsButton
              kind="secondary"
              size="sm"
              :icon="Launch20"
              @click="openExternalUrl(portalModalLoginUrl)"
            >
              {{ $t("tenants.open_login_page") }}
            </NsButton>
          </div>
        </div>

        <!-- Warning + 1-Click Activation if Customer Portal is Disabled -->
        <NsInlineNotification
          v-if="!loadingPortalUsers && !portalModal.customer_portal_enabled"
          kind="warning"
          :title="$t('tenants.portal_disabled_warning_title')"
          :description="$t('tenants.portal_disabled_warning_desc')"
          :actionLabel="$t('tenants.enable_portal_now_btn')"
          :loadingAction="enablingPortalInline"
          :showCloseButton="false"
          @action="enablePortalForCurrentTenant"
          class="mg-bottom-md"
        />

        <!-- Newly Set Credentials Copy Banner -->
        <NsInlineNotification
          v-if="issuedPortalCredentials"
          kind="success"
          :title="
            $t('tenants.portal_credentials_ready_title', {
              username: issuedPortalCredentials.username,
            })
          "
          :showCloseButton="true"
          @close="issuedPortalCredentials = null"
          class="mg-bottom-md"
        >
          <template #description>
            <div>
              <p class="mg-bottom-sm">
                {{ $t("tenants.portal_credentials_ready_desc") }}
              </p>
              <div class="token-secret-box__code mg-bottom-sm">
                <pre class="mono-text" style="margin: 0; white-space: pre-wrap">{{
                  formatCredentialsSummary(issuedPortalCredentials)
                }}</pre>
                <NsButton
                  kind="primary"
                  size="sm"
                  :icon="Copy16"
                  @click="
                    copySecret(
                      formatCredentialsSummary(issuedPortalCredentials)
                    )
                  "
                >
                  {{ $t("tenants.copy_credentials_summary_btn") }}
                </NsButton>
              </div>
            </div>
          </template>
        </NsInlineNotification>

        <!-- Existing Accounts List -->
        <h3 class="form-section-title mg-bottom-sm">
          {{
            $t("tenants.portal_existing_accounts_title", {
              count: portalModal.users.length,
            })
          }}
        </h3>

        <cv-skeleton-text
          v-if="loadingPortalUsers"
          :paragraph="true"
          :line-count="3"
        />
        <p
          v-else-if="!portalModal.users.length"
          class="form-section-desc mg-bottom-md"
        >
          {{ $t("tenants.portal_no_accounts") }}
        </p>
        <div v-else class="portal-users-list">
          <div
            v-for="usr in portalModal.users"
            :key="usr.username"
            class="portal-user-item"
          >
            <div class="portal-user-item__meta">
              <div class="table-row-actions">
                <strong class="mono-text">{{ usr.username }}</strong>
                <NsTag
                  :kind="usr.role === 'Editor' ? 'blue' : 'gray'"
                  :label="usr.role"
                />
                <NsTag
                  :kind="usr.disabled ? 'red' : 'green'"
                  :label="
                    usr.disabled
                      ? $t('tenants.portal_status_disabled')
                      : $t('tenants.portal_status_active')
                  "
                />
              </div>
              <div
                v-if="usr.full_name || usr.email"
                class="form-section-desc"
                style="margin: 0"
              >
                {{ usr.full_name }}
                <span v-if="usr.email">({{ usr.email }})</span>
              </div>
            </div>

            <div class="table-row-actions">
              <NsButton
                kind="ghost"
                size="sm"
                :icon="Edit16"
                :disabled="savingPortalUser"
                @click="startEditPortalUser(usr)"
              >
                {{ $t("tenants.portal_reset_edit_btn") }}
              </NsButton>
              <NsButton
                v-if="usr.disabled"
                kind="ghost"
                size="sm"
                :icon="Unlocked16"
                :disabled="savingPortalUser"
                @click="togglePortalUserDisabled(usr)"
              >
                {{ $t("tenants.portal_unlock_btn") }}
              </NsButton>
              <NsButton
                v-else
                kind="ghost"
                size="sm"
                :icon="Locked16"
                :disabled="savingPortalUser"
                @click="togglePortalUserDisabled(usr)"
              >
                {{ $t("tenants.portal_lock_btn") }}
              </NsButton>
              <NsButton
                kind="danger-ghost"
                size="sm"
                :icon="TrashCan16"
                :disabled="savingPortalUser"
                @click="submitDeletePortalUser(usr)"
              >
                {{ $t("common.delete") }}
              </NsButton>
            </div>
          </div>
        </div>

        <!-- Create / Edit Customer Account Form -->
        <div class="form-section-divider">
          <div class="page-toolbar mg-bottom-sm">
            <h3 class="form-section-title">
              {{
                isEditingPortalUser
                  ? $t("tenants.portal_form_edit_title", {
                      username: portalUserForm.username,
                    })
                  : $t("tenants.portal_form_create_title")
              }}
            </h3>
            <NsButton
              v-if="isEditingPortalUser"
              kind="ghost"
              size="sm"
              @click="resetPortalUserForm"
            >
              {{ $t("tenants.portal_cancel_edit_btn") }}
            </NsButton>
          </div>

          <cv-form @submit.prevent="submitSavePortalUser">
            <div class="form-grid-2">
              <NsTextInput
                v-model.trim="portalUserForm.username"
                :label="$t('tenants.portal_user_username_label')"
                :helper-text="$t('tenants.portal_user_username_helper')"
                placeholder="acme-admin"
                :disabled="isEditingPortalUser || savingPortalUser"
                :invalid-message="portalUserErrors.username"
              />
              <cv-select
                v-model="portalUserForm.role"
                :label="$t('tenants.portal_user_role_label')"
                :disabled="savingPortalUser"
              >
                <cv-select-option value="Viewer">
                  {{ $t("tenants.portal_role_viewer") }}
                </cv-select-option>
                <cv-select-option value="Editor">
                  {{ $t("tenants.portal_role_editor") }}
                </cv-select-option>
              </cv-select>
            </div>

            <div class="form-grid-2">
              <NsTextInput
                v-model.trim="portalUserForm.full_name"
                :label="$t('tenants.portal_user_fullname_label')"
                placeholder="Max Mustermann"
                :disabled="savingPortalUser"
              />
              <NsTextInput
                v-model.trim="portalUserForm.email"
                :label="$t('tenants.portal_user_email_label')"
                placeholder="m.mustermann@acme.example.com"
                :disabled="savingPortalUser"
                :invalid-message="portalUserErrors.email"
              />
            </div>

            <div class="password-gen-row">
              <div class="password-gen-row__input">
                <NsTextInput
                  v-model="portalUserForm.password"
                  :type="portalPasswordRevealed ? 'text' : 'password'"
                  :label="$t('tenants.portal_user_password_label')"
                  :helper-text="
                    isEditingPortalUser
                      ? $t('tenants.portal_user_password_edit_helper')
                      : $t('tenants.portal_user_password_create_helper')
                  "
                  :placeholder="
                    isEditingPortalUser
                      ? $t('common.unchanged_placeholder')
                      : $t('tenants.portal_password_placeholder')
                  "
                  :disabled="savingPortalUser"
                  :invalid-message="portalUserErrors.password"
                />
              </div>
              <NsButton
                kind="secondary"
                size="field"
                type="button"
                :icon="Password16"
                :disabled="savingPortalUser"
                @click="generateStrongPortalPassword"
              >
                {{ $t("tenants.generate_strong_password_btn") }}
              </NsButton>
            </div>

            <NsToggle
              v-model="portalUserForm.activeToggle"
              :label="$t('tenants.portal_user_account_status_label')"
              value="portalUserActive"
              :disabled="savingPortalUser"
              class="mg-top-md"
            >
              <template slot="text-left">
                {{ $t("tenants.portal_status_disabled") }}
              </template>
              <template slot="text-right">
                {{ $t("tenants.portal_status_active") }}
              </template>
            </NsToggle>
          </cv-form>
        </div>
      </template>
      <template slot="secondary-button">{{ $t("common.close") }}</template>
      <template slot="primary-button">
        {{
          isEditingPortalUser
            ? $t("tenants.save_portal_user_btn")
            : $t("tenants.create_portal_user_btn")
        }}
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
import { mapState, mapActions } from "vuex";
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
import UserMultiple20 from "@carbon/icons-vue/es/user--multiple/20";
import Launch20 from "@carbon/icons-vue/es/launch/20";
import Password16 from "@carbon/icons-vue/es/password/16";
import Locked16 from "@carbon/icons-vue/es/locked/16";
import Unlocked16 from "@carbon/icons-vue/es/unlocked/16";

const CUSTOMER_SLUG_RE = /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/;
const SITE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PORTAL_USER_RE = /^[a-zA-Z0-9._@-]{3,64}$/;
const PORTAL_SAVE_USER_RE = /^[a-zA-Z0-9._-]{3,64}$/;
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
      UserMultiple20,
      Launch20,
      Password16,
      Locked16,
      Unlocked16,
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
      showPortalUsersModal: false,
      loadingPortalUsers: false,
      savingPortalUser: false,
      enablingPortalInline: false,
      isEditingPortalUser: false,
      portalPasswordRevealed: false,
      portalTenantRow: null,
      portalModal: {
        customer: "",
        display_name: "",
        customer_portal_enabled: false,
        grafana_org_id: null,
        grafana_org_name: "",
        grafana_login_url: "",
        users: [],
      },
      portalUserErrors: {},
      portalUserForm: {
        username: "",
        full_name: "",
        email: "",
        role: "Viewer",
        activeToggle: true,
        password: "",
      },
      pendingPlainPassword: "",
      issuedPortalCredentials: null,
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
    ...mapState(["instanceName", "appName", "core", "grafanaUrl"]),
    i18nTableColumns() {
      return this.tableColumns.map((col) =>
        this.$t(`tenants.columns.${col}`)
      );
    },
    effectiveGrafanaLoginUrl() {
      const fromTenant = this.tenants.find((t) => t.grafana_login_url);
      if (fromTenant && fromTenant.grafana_login_url) {
        return fromTenant.grafana_login_url;
      }
      if (this.grafanaUrl) {
        const clean = this.grafanaUrl.replace(/\/+$/, "");
        return clean.endsWith("/login") ? clean : `${clean}/login`;
      }
      return "";
    },
    portalModalLoginUrl() {
      return this.portalModal.grafana_login_url || this.effectiveGrafanaLoginUrl;
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.loadTenants();
          if (!this.grafanaUrl) {
            this.loadOverviewUrl();
          }
        }
      },
    },
  },
  methods: {
    ...mapActions(["setGrafanaUrlInStore"]),
    clearFeedback() {
      this.feedbackBanner = { kind: "success", title: "", description: "" };
    },
    openExternalUrl(url) {
      if (url) {
        window.open(url, "_blank", "noopener,noreferrer");
      }
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
    async copyWithFeedback(text) {
      await this.copySecret(text);
      this.feedbackBanner = {
        kind: "success",
        title: this.$t("common.copied_to_clipboard"),
        description: text,
      };
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
    async loadOverviewUrl() {
      const taskAction = "get-overview";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, res) => {
          const out = (res && res.output) || {};
          if (out.grafana_url) {
            this.setGrafanaUrlInStore(out.grafana_url);
          }
        }
      );

      await this.to(
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
      const viewerUser = this.form.portal_viewer_username.trim();
      if (this.form.customer_portal_enabled && viewerUser) {
        if (!PORTAL_USER_RE.test(viewerUser)) {
          errors.portal_viewer_username = this.$t(
            "tenants.validation_portal_username"
          );
        }
        if (!this.isEditing && this.form.portal_viewer_password.length < 10) {
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

    // --- Multi-User Customer Portal Account Manager ---
    openPortalUsersModal(row) {
      this.portalTenantRow = row;
      this.issuedPortalCredentials = null;
      this.resetPortalUserForm();
      this.portalModal = {
        customer: row.customer,
        display_name: row.display_name || row.customer,
        customer_portal_enabled: Boolean(row.customer_portal_enabled),
        grafana_org_id: row.grafana_org_id || null,
        grafana_org_name: row.grafana_org_name || "",
        grafana_login_url: row.grafana_login_url || "",
        users: [],
      };
      this.showPortalUsersModal = true;
      this.loadPortalUsers(row.customer);
    },
    closePortalUsersModal() {
      this.showPortalUsersModal = false;
      this.pendingPlainPassword = "";
    },
    resetPortalUserForm() {
      this.isEditingPortalUser = false;
      this.portalPasswordRevealed = false;
      this.portalUserErrors = {};
      this.portalUserForm = {
        username: "",
        full_name: "",
        email: "",
        role: "Viewer",
        activeToggle: true,
        password: "",
      };
    },
    startEditPortalUser(usr) {
      this.isEditingPortalUser = true;
      this.portalPasswordRevealed = false;
      this.portalUserErrors = {};
      this.portalUserForm = {
        username: usr.username,
        full_name: usr.full_name || "",
        email: usr.email || "",
        role: usr.role === "Editor" ? "Editor" : "Viewer",
        activeToggle: !usr.disabled,
        password: "",
      };
    },
    generateStrongPortalPassword() {
      const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
      const lower = "abcdefghijkmnopqrstuvwxyz";
      const digits = "23456789";
      const symbols = "!@#$%&*-_";
      const all = upper + lower + digits + symbols;
      const rand = new Uint32Array(16);
      if (
        typeof globalThis !== "undefined" &&
        globalThis.crypto &&
        typeof globalThis.crypto.getRandomValues === "function"
      ) {
        globalThis.crypto.getRandomValues(rand);
      } else {
        for (let i = 0; i < rand.length; i += 1) {
          rand[i] = Math.floor(Math.random() * 0xffffffff);
        }
      }
      const chars = [
        upper[rand[0] % upper.length],
        lower[rand[1] % lower.length],
        digits[rand[2] % digits.length],
        symbols[rand[3] % symbols.length],
      ];
      for (let i = 4; i < 16; i += 1) {
        chars.push(all[rand[i] % all.length]);
      }
      for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = rand[i] % (i + 1);
        const tmp = chars[i];
        chars[i] = chars[j];
        chars[j] = tmp;
      }
      this.portalUserForm.password = chars.join("");
      this.portalPasswordRevealed = true;
    },
    formatCredentialsSummary(cred) {
      return this.$t("tenants.credentials_summary_template", {
        url: cred.url || "-",
        org: cred.org || "-",
        username: cred.username,
        role: cred.role,
        password: cred.password,
      });
    },
    async loadPortalUsers(customerSlug) {
      this.loadingPortalUsers = true;
      const taskAction = "list-portal-users";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.loadPortalUsersAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.loadPortalUsersCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { customer: customerSlug },
          extra: {
            title: this.$t("action.list-portal-users"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.loadingPortalUsers = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    loadPortalUsersAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loadingPortalUsers = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.portal_users_load_failed")
      );
    },
    loadPortalUsersCompleted(taskContext, taskResult) {
      this.loadingPortalUsers = false;
      const out = (taskResult && taskResult.output) || {};
      this.portalModal = {
        customer: out.customer || this.portalModal.customer,
        display_name: out.display_name || this.portalModal.display_name,
        customer_portal_enabled: Boolean(out.customer_portal_enabled),
        grafana_org_id:
          out.grafana_org_id !== undefined ? out.grafana_org_id : null,
        grafana_org_name: out.grafana_org_name || "",
        grafana_login_url: out.grafana_login_url || "",
        users: Array.isArray(out.users) ? out.users : [],
      };
    },
    async enablePortalForCurrentTenant() {
      const row =
        this.tenants.find((t) => t.customer === this.portalModal.customer) ||
        this.portalTenantRow;
      if (!row) {
        return;
      }
      this.enablingPortalInline = true;
      const payload = {
        customer: row.customer,
        display_name: row.display_name || row.customer,
        sites: Array.isArray(row.sites) && row.sites.length ? row.sites : ["hq"],
        contact_emails: Array.isArray(row.contact_emails)
          ? row.contact_emails
          : [],
        customer_portal_enabled: true,
        portal_viewer_username: row.portal_viewer_username || "",
        portal_viewer_password: "",
        notes: row.notes || "",
      };
      const taskAction = "save-tenant";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        (taskError) => {
          this.enablingPortalInline = false;
          this.createErrorNotificationForApp(
            taskError,
            this.$t("tenants.save_failed")
          );
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        () => {
          this.enablingPortalInline = false;
          this.loadPortalUsers(row.customer);
          this.loadTenants();
        }
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
        this.enablingPortalInline = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    validatePortalUserForm() {
      const errors = {};
      const username = (this.portalUserForm.username || "").trim();
      if (!PORTAL_SAVE_USER_RE.test(username)) {
        errors.username = this.$t("tenants.validation_portal_user_username");
      }
      const email = (this.portalUserForm.email || "").trim();
      if (email && !EMAIL_RE.test(email)) {
        errors.email = this.$t("tenants.validation_portal_user_email");
      }
      const pwd = this.portalUserForm.password || "";
      if (!this.isEditingPortalUser && pwd.length < 10) {
        errors.password = this.$t("tenants.validation_portal_user_password");
      } else if (this.isEditingPortalUser && pwd.length > 0 && pwd.length < 10) {
        errors.password = this.$t("tenants.validation_portal_user_password");
      }
      this.portalUserErrors = errors;
      return Object.keys(errors).length === 0;
    },
    async submitSavePortalUser() {
      if (!this.validatePortalUserForm()) {
        return;
      }
      const pwd = this.portalUserForm.password || "";
      const passwordUnchanged = Boolean(
        this.isEditingPortalUser && pwd.length === 0
      );
      this.pendingPlainPassword = pwd;
      const payload = {
        customer: this.portalModal.customer,
        username: this.portalUserForm.username.trim(),
        full_name: (this.portalUserForm.full_name || "").trim(),
        email: (this.portalUserForm.email || "").trim(),
        role: this.portalUserForm.role === "Editor" ? "Editor" : "Viewer",
        disabled: !this.portalUserForm.activeToggle,
        password: pwd,
        password_unchanged: passwordUnchanged,
      };
      await this.dispatchSavePortalUser(payload);
    },
    async togglePortalUserDisabled(usr) {
      this.pendingPlainPassword = "";
      const payload = {
        customer: this.portalModal.customer,
        username: usr.username,
        full_name: usr.full_name || "",
        email: usr.email || "",
        role: usr.role === "Editor" ? "Editor" : "Viewer",
        disabled: !usr.disabled,
        password: "",
        password_unchanged: true,
      };
      await this.dispatchSavePortalUser(payload);
    },
    async dispatchSavePortalUser(payload) {
      this.savingPortalUser = true;
      const taskAction = "save-portal-user";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.savePortalUserAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.savePortalUserValidationFailed
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.savePortalUserCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.save-portal-user"),
            description: payload.username,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.savingPortalUser = false;
        this.pendingPlainPassword = "";
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    savePortalUserAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.savingPortalUser = false;
      this.pendingPlainPassword = "";
      this.createErrorNotificationForApp(
        taskError,
        this.$t("tenants.portal_user_save_failed")
      );
    },
    savePortalUserValidationFailed(validationErrors) {
      this.savingPortalUser = false;
      this.pendingPlainPassword = "";
      const mapped = {};
      const errList = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];
      errList.forEach((item) => {
        const key = item.field || item.parameter || "username";
        mapped[key] = this.$te(`validation.${item.error}`)
          ? this.$t(`validation.${item.error}`)
          : item.error;
      });
      this.portalUserErrors = mapped;
    },
    savePortalUserCompleted(taskContext, taskResult) {
      this.savingPortalUser = false;
      const out = (taskResult && taskResult.output) || {};
      const savedUser = out.user || {};
      if (this.pendingPlainPassword) {
        this.issuedPortalCredentials = {
          url: out.grafana_login_url || this.portalModalLoginUrl,
          org:
            out.grafana_org_name ||
            this.portalModal.grafana_org_name ||
            `Customer: ${this.portalModal.display_name} (${this.portalModal.customer})`,
          username: savedUser.username || this.portalUserForm.username,
          role: savedUser.role || this.portalUserForm.role,
          password: this.pendingPlainPassword,
        };
      }
      this.pendingPlainPassword = "";
      this.resetPortalUserForm();
      this.loadPortalUsers(this.portalModal.customer);
      this.loadTenants();
    },
    async submitDeletePortalUser(usr) {
      this.savingPortalUser = true;
      const payload = {
        customer: this.portalModal.customer,
        username: usr.username,
      };
      const taskAction = "delete-portal-user";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        (taskError, taskContext) => {
          console.error(`${taskContext.action} aborted`, taskError);
          this.savingPortalUser = false;
          this.createErrorNotificationForApp(
            taskError,
            this.$t("tenants.portal_user_delete_failed")
          );
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        () => {
          this.savingPortalUser = false;
          if (
            this.isEditingPortalUser &&
            this.portalUserForm.username === usr.username
          ) {
            this.resetPortalUserForm();
          }
          this.loadPortalUsers(this.portalModal.customer);
          this.loadTenants();
        }
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.delete-portal-user"),
            description: usr.username,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.savingPortalUser = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
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
