<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("alerting.title") }}</h1>
      <div class="page-toolbar__actions">
        <NsButton
          kind="secondary"
          size="field"
          :icon="SendAlt20"
          @click="openTestAlertModal"
        >
          {{ $t("alerting.send_test_alert") }}
        </NsButton>
        <NsButton
          kind="secondary"
          size="field"
          :icon="Renew20"
          :disabled="loadingAlerting || loadingSilences"
          @click="refreshActiveData"
        >
          {{ $t("common.refresh") }}
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

    <cv-tabs :aria-label="$t('alerting.tabs_aria')">
      <!-- TAB 1: Notification Channels & Rule Packs -->
      <cv-tab :label="$t('alerting.tab_channels_rules')">
        <div class="mg-top-md">
          <cv-skeleton-text
            v-if="loadingAlerting"
            :paragraph="true"
            :line-count="8"
          />

          <cv-form v-else @submit.prevent="submitConfigureAlerting">
            <!-- Grouping & Repeat Timers -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.routing_timers_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.routing_timers_desc") }}
                  </p>
                </div>
              </div>
              <div class="form-grid-2">
                <NsTextInput
                  v-model.trim="form.group_wait"
                  :label="$t('alerting.group_wait_label')"
                  placeholder="30s"
                  :disabled="savingAlerting"
                  :invalid-message="validationErrors.group_wait"
                />
                <NsTextInput
                  v-model.trim="form.group_interval"
                  :label="$t('alerting.group_interval_label')"
                  placeholder="5m"
                  :disabled="savingAlerting"
                  :invalid-message="validationErrors.group_interval"
                />
              </div>
              <div class="form-grid-2">
                <NsTextInput
                  v-model.trim="form.repeat_interval"
                  :label="$t('alerting.repeat_interval_label')"
                  placeholder="4h"
                  :disabled="savingAlerting"
                  :invalid-message="validationErrors.repeat_interval"
                />
              </div>
            </section>

            <!-- 1. NS8 Smarthost / SMTP Email -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.smarthost_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{
                      ns8SmarthostAvailable
                        ? $t("alerting.ns8_smarthost_detected", {
                            host: ns8SmarthostHost || "cluster-smarthost",
                          })
                        : $t("alerting.ns8_smarthost_not_configured")
                    }}
                  </p>
                </div>
                <NsToggle
                  v-model="form.smarthost_email.enabled"
                  :label="$t('common.status')"
                  value="smarthostEmailEnabled"
                  :form-item="false"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>
              </div>

              <div v-if="form.smarthost_email.enabled">
                <NsToggle
                  v-model="form.smarthost_email.use_ns8_smarthost"
                  :label="$t('alerting.use_ns8_smarthost')"
                  value="useNs8Smarthost"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>

                <div
                  v-if="!form.smarthost_email.use_ns8_smarthost"
                  class="form-grid-2"
                >
                  <NsTextInput
                    v-model.trim="form.smarthost_email.smtp_host"
                    :label="$t('alerting.smtp_host')"
                    placeholder="smtp.msp.example.com"
                    :disabled="savingAlerting"
                    :invalid-message="validationErrors.smtp_host"
                  />
                  <NsTextInput
                    v-model="form.smarthost_email.smtp_port"
                    type="number"
                    :label="$t('alerting.smtp_port')"
                    placeholder="587"
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model.trim="form.smarthost_email.smtp_user"
                    :label="$t('alerting.smtp_user')"
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model="form.smarthost_email.smtp_password"
                    type="password"
                    :label="$t('alerting.smtp_password')"
                    :placeholder="
                      secretFlags.has_smtp_password
                        ? $t('common.unchanged_placeholder')
                        : ''
                    "
                    :disabled="savingAlerting"
                  />
                </div>

                <NsToggle
                  v-if="!form.smarthost_email.use_ns8_smarthost"
                  v-model="form.smarthost_email.smtp_tls"
                  :label="$t('alerting.smtp_tls')"
                  value="smtpTls"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>

                <div class="form-grid-2">
                  <NsTextInput
                    v-model.trim="form.smarthost_email.from_address"
                    :label="$t('alerting.from_address')"
                    placeholder="monitoring@msp.example.com"
                    :disabled="savingAlerting"
                    :invalid-message="validationErrors.from_address"
                  />
                  <NsTextInput
                    v-model="form.defaultToAddressesText"
                    :label="$t('alerting.default_to_addresses')"
                    placeholder="noc@msp.example.com, ops@msp.example.com"
                    :disabled="savingAlerting"
                    :invalid-message="validationErrors.default_to_addresses"
                  />
                </div>

                <NsToggle
                  v-model="form.smarthost_email.send_resolved"
                  :label="$t('alerting.send_resolved')"
                  value="emailSendResolved"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>
              </div>
            </section>

            <!-- 2. PSA / Ticketing Webhook -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.webhook_psa_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.webhook_psa_desc") }}
                  </p>
                </div>
                <NsToggle
                  v-model="form.webhook_psa.enabled"
                  :label="$t('common.status')"
                  value="webhookPsaEnabled"
                  :form-item="false"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>
              </div>

              <div v-if="form.webhook_psa.enabled">
                <div class="form-grid-2">
                  <NsTextInput
                    v-model.trim="form.webhook_psa.url"
                    :label="$t('alerting.webhook_url')"
                    placeholder="https://psa.msp.example.com/api/alerts/webhook"
                    :disabled="savingAlerting"
                    :invalid-message="validationErrors.webhook_url"
                  />
                  <NsTextInput
                    v-model="form.webhook_psa.auth_secret"
                    type="password"
                    :label="$t('alerting.webhook_auth_secret')"
                    :placeholder="
                      secretFlags.has_auth_secret
                        ? $t('common.unchanged_placeholder')
                        : ''
                    "
                    :disabled="savingAlerting"
                  />
                </div>
                <NsToggle
                  v-model="form.webhook_psa.send_resolved"
                  :label="$t('alerting.send_resolved')"
                  value="webhookSendResolved"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>
              </div>
            </section>

            <!-- 3. Team Chat (MS Teams & Slack) -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.chat_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.chat_desc") }}
                  </p>
                </div>
              </div>

              <div class="form-grid-2">
                <div>
                  <NsToggle
                    v-model="form.chat.teams_enabled"
                    :label="$t('alerting.teams_enabled')"
                    value="teamsEnabled"
                    :disabled="savingAlerting"
                  >
                    <template slot="text-left">
                      {{ $t("common.disabled") }}
                    </template>
                    <template slot="text-right">
                      {{ $t("common.enabled") }}
                    </template>
                  </NsToggle>
                  <NsTextInput
                    v-if="form.chat.teams_enabled"
                    v-model.trim="form.chat.teams_webhook_url"
                    type="password"
                    :label="$t('alerting.teams_webhook_url')"
                    :placeholder="
                      secretFlags.has_teams_webhook_url
                        ? $t('common.unchanged_placeholder')
                        : 'https://outlook.office.com/webhook/...'
                    "
                    :disabled="savingAlerting"
                  />
                </div>

                <div>
                  <NsToggle
                    v-model="form.chat.slack_enabled"
                    :label="$t('alerting.slack_enabled')"
                    value="slackEnabled"
                    :disabled="savingAlerting"
                  >
                    <template slot="text-left">
                      {{ $t("common.disabled") }}
                    </template>
                    <template slot="text-right">
                      {{ $t("common.enabled") }}
                    </template>
                  </NsToggle>
                  <div v-if="form.chat.slack_enabled">
                    <NsTextInput
                      v-model.trim="form.chat.slack_webhook_url"
                      type="password"
                      :label="$t('alerting.slack_webhook_url')"
                      :placeholder="
                        secretFlags.has_slack_webhook_url
                          ? $t('common.unchanged_placeholder')
                          : 'https://hooks.slack.com/services/...'
                      "
                      :disabled="savingAlerting"
                    />
                    <NsTextInput
                      v-model.trim="form.chat.slack_channel"
                      :label="$t('alerting.slack_channel')"
                      placeholder="#msp-alerts"
                      :disabled="savingAlerting"
                    />
                  </div>
                </div>
              </div>

              <NsToggle
                v-if="form.chat.teams_enabled || form.chat.slack_enabled"
                v-model="form.chat.send_resolved"
                :label="$t('alerting.send_resolved')"
                value="chatSendResolved"
                :disabled="savingAlerting"
              >
                <template slot="text-left">{{ $t("common.no") }}</template>
                <template slot="text-right">{{ $t("common.yes") }}</template>
              </NsToggle>
            </section>

            <!-- 4. Mobile Push (Ntfy / Telegram / Gotify) -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.push_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.push_desc") }}
                  </p>
                </div>
                <NsToggle
                  v-model="form.push.enabled"
                  :label="$t('common.status')"
                  value="pushEnabled"
                  :form-item="false"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>
              </div>

              <div v-if="form.push.enabled">
                <div class="form-grid-2">
                  <cv-select
                    v-model="form.push.provider"
                    :label="$t('alerting.push_provider')"
                    :disabled="savingAlerting"
                  >
                    <cv-select-option value="ntfy">Ntfy</cv-select-option>
                    <cv-select-option value="telegram">
                      Telegram
                    </cv-select-option>
                    <cv-select-option value="gotify">Gotify</cv-select-option>
                    <cv-select-option value="none">
                      {{ $t("common.none") }}
                    </cv-select-option>
                  </cv-select>

                  <cv-select
                    v-model="form.push.min_severity"
                    :label="$t('alerting.min_severity')"
                    :disabled="savingAlerting"
                  >
                    <cv-select-option value="critical">
                      {{ $t("alerting.severity_critical_only") }}
                    </cv-select-option>
                    <cv-select-option value="warning">
                      {{ $t("alerting.severity_warning_and_critical") }}
                    </cv-select-option>
                  </cv-select>
                </div>

                <div
                  v-if="form.push.provider === 'ntfy'"
                  class="form-grid-2 mg-top-md"
                >
                  <NsTextInput
                    v-model.trim="form.push.ntfy_url"
                    :label="$t('alerting.ntfy_url')"
                    placeholder="https://ntfy.sh"
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model.trim="form.push.ntfy_topic"
                    :label="$t('alerting.ntfy_topic')"
                    placeholder="msp-oncall-critical"
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model="form.push.ntfy_token"
                    type="password"
                    :label="$t('alerting.ntfy_token')"
                    :placeholder="
                      secretFlags.has_ntfy_token
                        ? $t('common.unchanged_placeholder')
                        : ''
                    "
                    :disabled="savingAlerting"
                  />
                </div>

                <div
                  v-if="form.push.provider === 'telegram'"
                  class="form-grid-2 mg-top-md"
                >
                  <NsTextInput
                    v-model="form.push.telegram_bot_token"
                    type="password"
                    :label="$t('alerting.telegram_bot_token')"
                    :placeholder="
                      secretFlags.has_telegram_bot_token
                        ? $t('common.unchanged_placeholder')
                        : ''
                    "
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model.trim="form.push.telegram_chat_id"
                    :label="$t('alerting.telegram_chat_id')"
                    placeholder="-1001234567890"
                    :disabled="savingAlerting"
                  />
                </div>

                <div
                  v-if="form.push.provider === 'gotify'"
                  class="form-grid-2 mg-top-md"
                >
                  <NsTextInput
                    v-model.trim="form.push.gotify_url"
                    :label="$t('alerting.gotify_url')"
                    placeholder="https://gotify.msp.example.com"
                    :disabled="savingAlerting"
                  />
                  <NsTextInput
                    v-model="form.push.gotify_token"
                    type="password"
                    :label="$t('alerting.gotify_token')"
                    :placeholder="
                      secretFlags.has_gotify_token
                        ? $t('common.unchanged_placeholder')
                        : ''
                    "
                    :disabled="savingAlerting"
                  />
                </div>
              </div>
            </section>

            <!-- 5. Per-Customer Email Routing -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.customer_email_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.customer_email_desc") }}
                  </p>
                </div>
                <NsToggle
                  v-model="form.customer_email_routing.enabled"
                  :label="$t('common.status')"
                  value="customerEmailEnabled"
                  :form-item="false"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>
              </div>

              <div
                v-if="form.customer_email_routing.enabled"
                class="form-grid-2"
              >
                <cv-select
                  v-model="form.customer_email_routing.min_severity"
                  :label="$t('alerting.min_severity')"
                  :disabled="savingAlerting"
                >
                  <cv-select-option value="critical">
                    {{ $t("alerting.severity_critical_only") }}
                  </cv-select-option>
                  <cv-select-option value="warning">
                    {{ $t("alerting.severity_warning_and_critical") }}
                  </cv-select-option>
                </cv-select>

                <NsToggle
                  v-model="form.customer_email_routing.send_resolved"
                  :label="$t('alerting.send_resolved')"
                  value="customerEmailSendResolved"
                  :disabled="savingAlerting"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>
              </div>
            </section>

            <!-- 6. MSP Standard Prometheus Alert Rule Packs -->
            <section class="section-card">
              <div class="section-card__header">
                <div>
                  <h2 class="section-card__title">
                    {{ $t("alerting.rule_packs_title") }}
                  </h2>
                  <p class="section-card__subtitle">
                    {{ $t("alerting.rule_packs_desc") }}
                  </p>
                </div>
              </div>

              <div class="component-badge-grid">
                <div
                  v-for="pack in rulePacks"
                  :key="pack.pack_id"
                  class="component-badge-item"
                >
                  <div>
                    <div class="component-badge-item__name">
                      {{ $t(`alerting.packs.${pack.pack_id}`) }}
                    </div>
                    <div class="mono-text">
                      {{ pack.filename }}
                      <span v-if="pack.rules_count">
                        ({{ pack.rules_count }})
                      </span>
                    </div>
                  </div>
                  <NsToggle
                    v-model="pack.enabled"
                    :label="pack.pack_id"
                    :hide-label="true"
                    :form-item="false"
                    :value="pack.pack_id"
                    :disabled="savingAlerting"
                  >
                    <template slot="text-left">{{ $t("common.off") }}</template>
                    <template slot="text-right">{{ $t("common.on") }}</template>
                  </NsToggle>
                </div>
              </div>
            </section>

            <NsButton
              kind="primary"
              size="field"
              :icon="Save20"
              :loading="savingAlerting"
              :disabled="savingAlerting"
              type="submit"
            >
              {{ $t("alerting.save_alerting_btn") }}
            </NsButton>
          </cv-form>
        </div>
      </cv-tab>

      <!-- TAB 2: Maintenance Windows / Silences -->
      <cv-tab :label="$t('alerting.tab_silences')">
        <div class="mg-top-md">
          <section class="section-card">
            <div class="page-toolbar">
              <div class="form-grid-2">
                <cv-select
                  v-model="silenceFilter.customer"
                  :label="$t('alerting.filter_customer')"
                  @change="loadSilences"
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

                <NsToggle
                  v-model="silenceFilter.include_expired"
                  :label="$t('alerting.include_expired')"
                  value="includeExpiredSilences"
                  @change="loadSilences"
                >
                  <template slot="text-left">{{ $t("common.no") }}</template>
                  <template slot="text-right">{{ $t("common.yes") }}</template>
                </NsToggle>
              </div>

              <NsButton
                kind="primary"
                size="field"
                :icon="Add20"
                @click="openCreateSilenceModal"
              >
                {{ $t("alerting.create_silence_btn") }}
              </NsButton>
            </div>

            <NsDataTable
              :allRows="silences"
              :columns="i18nSilenceColumns"
              :rawColumns="silenceColumns"
              :isSearchable="true"
              :searchPlaceholder="$t('alerting.search_silences')"
              :searchClearLabel="$t('common.clear_search')"
              :noSearchResultsLabel="$t('common.no_results')"
              :noSearchResultsDescription="$t('common.try_changing_search')"
              :isLoading="loadingSilences"
              :skeletonRows="4"
              :itemsPerPageLabel="$t('pagination.items_per_page')"
              :rangeOfTotalItemsLabel="$t('pagination.range_of_total_items')"
              :ofTotalPagesLabel="$t('pagination.of_total_pages')"
              :backwardText="$t('pagination.previous_page')"
              :forwardText="$t('pagination.next_page')"
              :pageNumberLabel="$t('pagination.page_number')"
              @updatePage="silencePage = $event"
            >
              <template slot="empty-state">
                <NsEmptyState :title="$t('alerting.silences_empty_title')">
                  <template #description>
                    <div>{{ $t("alerting.silences_empty_desc") }}</div>
                    <NsButton
                      kind="primary"
                      size="field"
                      :icon="Add20"
                      class="mg-top-md"
                      @click="openCreateSilenceModal"
                    >
                      {{ $t("alerting.create_silence_btn") }}
                    </NsButton>
                  </template>
                </NsEmptyState>
              </template>

              <template slot="data">
                <cv-data-table-row
                  v-for="(row, rowIndex) in silencePage"
                  :key="row.id || `${rowIndex}`"
                  :value="row.id || `${rowIndex}`"
                >
                  <cv-data-table-cell>
                    <NsTag
                      :kind="
                        row.state === 'active'
                          ? 'green'
                          : row.state === 'pending'
                          ? 'blue'
                          : 'gray'
                      "
                      :label="$t(`alerting.silence_state_${row.state}`)"
                    />
                  </cv-data-table-cell>

                  <cv-data-table-cell>
                    <div class="tag-list">
                      <NsTag
                        v-for="(m, idx) in row.matchers || []"
                        :key="idx"
                        kind="gray"
                        :label="formatMatcher(m)"
                      />
                      <NsTag
                        v-if="!row.matchers || !row.matchers.length"
                        kind="blue"
                        :label="$t('alerting.global_maintenance')"
                      />
                    </div>
                  </cv-data-table-cell>

                  <cv-data-table-cell>
                    <div class="mono-text">{{ row.starts_at }}</div>
                    <div class="mono-text">→ {{ row.ends_at }}</div>
                  </cv-data-table-cell>

                  <cv-data-table-cell>
                    <div>{{ row.comment }}</div>
                    <div class="form-section-desc">{{ row.created_by }}</div>
                  </cv-data-table-cell>

                  <cv-data-table-cell>
                    <NsButton
                      v-if="row.state !== 'expired'"
                      kind="danger-ghost"
                      size="sm"
                      :icon="TrashCan16"
                      @click="expireSilence(row)"
                    >
                      {{ $t("alerting.expire_silence_btn") }}
                    </NsButton>
                  </cv-data-table-cell>
                </cv-data-table-row>
              </template>
            </NsDataTable>
          </section>
        </div>
      </cv-tab>
    </cv-tabs>

    <!-- Send Test Alert Modal -->
    <NsModal
      size="small"
      :visible="showTestModal"
      :primary-button-disabled="sendingTestAlert"
      :isLoading="sendingTestAlert"
      @modal-hidden="showTestModal = false"
      @primary-click="submitTestAlert"
    >
      <template slot="title">{{ $t("alerting.send_test_alert") }}</template>
      <template slot="content">
        <cv-select
          v-model="testAlertForm.channel"
          :label="$t('alerting.test_channel_label')"
          :disabled="sendingTestAlert"
        >
          <cv-select-option value="all">
            {{ $t("alerting.test_channels.all") }}
          </cv-select-option>
          <cv-select-option value="smarthost_email">
            {{ $t("alerting.test_channels.smarthost_email") }}
          </cv-select-option>
          <cv-select-option value="webhook_psa">
            {{ $t("alerting.test_channels.webhook_psa") }}
          </cv-select-option>
          <cv-select-option value="teams">
            {{ $t("alerting.test_channels.teams") }}
          </cv-select-option>
          <cv-select-option value="slack">
            {{ $t("alerting.test_channels.slack") }}
          </cv-select-option>
          <cv-select-option value="push">
            {{ $t("alerting.test_channels.push") }}
          </cv-select-option>
          <cv-select-option value="customer_email">
            {{ $t("alerting.test_channels.customer_email") }}
          </cv-select-option>
        </cv-select>

        <cv-select
          v-if="testAlertForm.channel === 'customer_email' && tenants.length"
          v-model="testAlertForm.customer"
          :label="$t('targets.customer_label')"
          class="mg-top-md"
          :disabled="sendingTestAlert"
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
          v-else-if="testAlertForm.channel === 'customer_email'"
          v-model.trim="testAlertForm.customer"
          :label="$t('targets.customer_label')"
          placeholder="acme-corp"
          class="mg-top-md"
          :disabled="sendingTestAlert"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("alerting.send_test_alert") }}
      </template>
    </NsModal>

    <!-- Create Maintenance Window (Silence) Modal -->
    <NsModal
      size="default"
      :visible="showSilenceModal"
      :primary-button-disabled="creatingSilence"
      :isLoading="creatingSilence"
      @modal-hidden="showSilenceModal = false"
      @primary-click="submitCreateSilence"
    >
      <template slot="title">{{ $t("alerting.create_silence_btn") }}</template>
      <template slot="content">
        <cv-form @submit.prevent="submitCreateSilence">
          <div class="form-grid-2">
            <cv-select
              v-model="silenceForm.customer"
              :label="$t('targets.customer_label')"
              :disabled="creatingSilence"
              @change="onSilenceCustomerChange"
            >
              <cv-select-option value="*">
                {{ $t("alerting.all_customers_global") }}
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
              v-model="silenceForm.site"
              :label="$t('targets.site_label')"
              :disabled="creatingSilence || silenceForm.customer === '*'"
            >
              <cv-select-option value="">
                {{ $t("alerting.all_sites") }}
              </cv-select-option>
              <cv-select-option
                v-for="site in availableSilenceSites"
                :key="site"
                :value="site"
              >
                {{ site }}
              </cv-select-option>
            </cv-select>
          </div>

          <div class="form-grid-2 mg-top-md">
            <cv-select
              v-model="silenceForm.device_role"
              :label="$t('targets.device_role_label')"
              :disabled="creatingSilence"
            >
              <cv-select-option value="">
                {{ $t("alerting.all_device_roles") }}
              </cv-select-option>
              <cv-select-option
                v-for="role in deviceRoles"
                :key="role"
                :value="role"
              >
                {{ $t(`targets.roles.${role}`) }}
              </cv-select-option>
            </cv-select>

            <cv-select
              v-model="silenceForm.durationPreset"
              :label="$t('alerting.duration_preset_label')"
              :disabled="creatingSilence"
              @change="applyDurationPreset"
            >
              <cv-select-option value="1h">1h</cv-select-option>
              <cv-select-option value="2h">2h</cv-select-option>
              <cv-select-option value="4h">4h</cv-select-option>
              <cv-select-option value="8h">8h</cv-select-option>
              <cv-select-option value="24h">24h</cv-select-option>
              <cv-select-option value="custom">
                {{ $t("alerting.duration_custom") }}
              </cv-select-option>
            </cv-select>
          </div>

          <div class="form-grid-2 mg-top-md">
            <NsTextInput
              v-model.trim="silenceForm.starts_at"
              :label="$t('alerting.starts_at_label')"
              placeholder="2026-11-21T02:00:00Z"
              :disabled="creatingSilence"
              :invalid-message="silenceErrors.starts_at"
            />
            <NsTextInput
              v-model.trim="silenceForm.ends_at"
              :label="$t('alerting.ends_at_label')"
              placeholder="2026-11-21T06:00:00Z"
              :disabled="creatingSilence"
              :invalid-message="silenceErrors.ends_at"
            />
          </div>

          <NsTextInput
            v-model="silenceForm.extraMatchersText"
            :label="$t('alerting.extra_matchers_label')"
            :helper-text="$t('alerting.extra_matchers_helper')"
            placeholder="alertname=WindowsNodeRebooted, instance=~srv.*"
            :disabled="creatingSilence"
            :invalid-message="silenceErrors.extra_matchers"
          />

          <div class="form-grid-2">
            <NsTextInput
              v-model.trim="silenceForm.created_by"
              :label="$t('alerting.created_by_label')"
              placeholder="msp-admin"
              :disabled="creatingSilence"
              :invalid-message="silenceErrors.created_by"
            />
            <NsTextInput
              v-model.trim="silenceForm.comment"
              :label="$t('alerting.comment_label')"
              :placeholder="$t('alerting.comment_placeholder')"
              :disabled="creatingSilence"
              :invalid-message="silenceErrors.comment"
            />
          </div>
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("alerting.create_silence_btn") }}
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
import Save20 from "@carbon/icons-vue/es/save/20";
import SendAlt20 from "@carbon/icons-vue/es/send--alt/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Add20 from "@carbon/icons-vue/es/add/20";
import TrashCan16 from "@carbon/icons-vue/es/trash-can/16";

const DEFAULT_RULE_PACKS = [
  { pack_id: "ns8-cluster", filename: "ns8-cluster.yml", enabled: true, rules_count: 0 },
  { pack_id: "linux-node", filename: "linux-node.yml", enabled: true, rules_count: 0 },
  { pack_id: "windows-node", filename: "windows-node.yml", enabled: true, rules_count: 0 },
  { pack_id: "proxmox-ve", filename: "proxmox-ve.yml", enabled: true, rules_count: 0 },
  { pack_id: "blackbox-web-ssl", filename: "blackbox-web-ssl.yml", enabled: true, rules_count: 0 },
  { pack_id: "snmp-network-ups", filename: "snmp-network-ups.yml", enabled: true, rules_count: 0 },
];

export default {
  name: "Alerting",
  mixins: [TaskService, IconService, UtilService, PageTitleService],
  pageTitle() {
    return `${this.$t("alerting.title")} - ${this.appName}`;
  },
  data() {
    return {
      Save20,
      SendAlt20,
      Renew20,
      Add20,
      TrashCan16,
      loadingAlerting: false,
      savingAlerting: false,
      loadingSilences: false,
      ns8SmarthostAvailable: false,
      ns8SmarthostHost: "",
      tenants: [],
      validationErrors: {},
      feedbackBanner: {
        kind: "success",
        title: "",
        description: "",
      },
      secretFlags: {
        has_smtp_password: false,
        has_auth_secret: false,
        has_teams_webhook_url: false,
        has_slack_webhook_url: false,
        has_ntfy_token: false,
        has_telegram_bot_token: false,
        has_gotify_token: false,
      },
      form: {
        group_wait: "30s",
        group_interval: "5m",
        repeat_interval: "4h",
        defaultToAddressesText: "",
        smarthost_email: {
          enabled: false,
          use_ns8_smarthost: true,
          smtp_host: "",
          smtp_port: "587",
          smtp_user: "",
          smtp_password: "",
          smtp_tls: true,
          from_address: "",
          send_resolved: true,
        },
        webhook_psa: {
          enabled: false,
          url: "",
          auth_secret: "",
          send_resolved: true,
        },
        chat: {
          teams_enabled: false,
          teams_webhook_url: "",
          slack_enabled: false,
          slack_webhook_url: "",
          slack_channel: "",
          send_resolved: true,
        },
        push: {
          enabled: false,
          provider: "ntfy",
          min_severity: "critical",
          ntfy_url: "https://ntfy.sh",
          ntfy_topic: "",
          ntfy_token: "",
          telegram_bot_token: "",
          telegram_chat_id: "",
          gotify_url: "",
          gotify_token: "",
        },
        customer_email_routing: {
          enabled: false,
          min_severity: "critical",
          send_resolved: true,
        },
      },
      rulePacks: DEFAULT_RULE_PACKS.map((p) => Object.assign({}, p)),
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
      silences: [],
      silencePage: [],
      silenceColumns: [
        "state",
        "matchers",
        "window",
        "comment",
        "actions",
      ],
      silenceFilter: {
        customer: "",
        include_expired: false,
      },
      showTestModal: false,
      sendingTestAlert: false,
      testAlertForm: {
        channel: "all",
        customer: "",
      },
      showSilenceModal: false,
      creatingSilence: false,
      silenceErrors: {},
      silenceForm: {
        customer: "*",
        site: "",
        device_role: "",
        durationPreset: "2h",
        starts_at: "",
        ends_at: "",
        extraMatchersText: "",
        created_by: "msp-admin",
        comment: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "appName", "core"]),
    i18nSilenceColumns() {
      return this.silenceColumns.map((col) =>
        this.$t(`alerting.silence_columns.${col}`)
      );
    },
    availableSilenceSites() {
      const found = this.tenants.find(
        (t) => t.customer === this.silenceForm.customer
      );
      return found && Array.isArray(found.sites) ? found.sites : [];
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core) {
          this.loadTenantsLookup();
          this.refreshActiveData();
        }
      },
    },
  },
  methods: {
    clearFeedback() {
      this.feedbackBanner = { kind: "success", title: "", description: "" };
    },
    refreshActiveData() {
      this.loadAlerting();
      this.loadSilences();
    },
    formatMatcher(m) {
      if (!m) {
        return "";
      }
      const op = m.is_equal === false
        ? m.is_regex
          ? "!~"
          : "!="
        : m.is_regex
        ? "=~"
        : "=";
      return `${m.name}${op}"${m.value}"`;
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
    async loadAlerting() {
      this.loadingAlerting = true;
      const taskAction = "get-alerting";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.loadAlertingAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.loadAlertingCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {},
          extra: {
            title: this.$t("action.get-alerting"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.loadingAlerting = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    loadAlertingAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loadingAlerting = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.cannot_load_alerting")
      );
    },
    loadAlertingCompleted(taskContext, taskResult) {
      this.loadingAlerting = false;
      const out = (taskResult && taskResult.output) || {};
      this.ns8SmarthostAvailable = Boolean(out.ns8_smarthost_available);
      this.ns8SmarthostHost = out.ns8_smarthost_host || "";
      this.form.group_wait = out.group_wait || "30s";
      this.form.group_interval = out.group_interval || "5m";
      this.form.repeat_interval = out.repeat_interval || "4h";

      const se = out.smarthost_email || {};
      this.secretFlags.has_smtp_password = Boolean(se.has_smtp_password);
      this.form.smarthost_email = {
        enabled: Boolean(se.enabled),
        use_ns8_smarthost:
          se.use_ns8_smarthost !== undefined
            ? Boolean(se.use_ns8_smarthost)
            : true,
        smtp_host: se.smtp_host || "",
        smtp_port: String(se.smtp_port || 587),
        smtp_user: se.smtp_user || "",
        smtp_password: "",
        smtp_tls: se.smtp_tls !== undefined ? Boolean(se.smtp_tls) : true,
        from_address: se.from_address || "",
        send_resolved:
          se.send_resolved !== undefined ? Boolean(se.send_resolved) : true,
      };
      this.form.defaultToAddressesText = Array.isArray(se.default_to_addresses)
        ? se.default_to_addresses.join(", ")
        : "";

      const wp = out.webhook_psa || {};
      this.secretFlags.has_auth_secret = Boolean(wp.has_auth_secret);
      this.form.webhook_psa = {
        enabled: Boolean(wp.enabled),
        url: wp.url || "",
        auth_secret: "",
        send_resolved:
          wp.send_resolved !== undefined ? Boolean(wp.send_resolved) : true,
      };

      const ch = out.chat || {};
      this.secretFlags.has_teams_webhook_url = Boolean(
        ch.has_teams_webhook_url
      );
      this.secretFlags.has_slack_webhook_url = Boolean(
        ch.has_slack_webhook_url
      );
      this.form.chat = {
        teams_enabled: Boolean(ch.teams_enabled),
        teams_webhook_url: "",
        slack_enabled: Boolean(ch.slack_enabled),
        slack_webhook_url: "",
        slack_channel: ch.slack_channel || "",
        send_resolved:
          ch.send_resolved !== undefined ? Boolean(ch.send_resolved) : true,
      };

      const pu = out.push || {};
      this.secretFlags.has_ntfy_token = Boolean(pu.has_ntfy_token);
      this.secretFlags.has_telegram_bot_token = Boolean(
        pu.has_telegram_bot_token
      );
      this.secretFlags.has_gotify_token = Boolean(pu.has_gotify_token);
      this.form.push = {
        enabled: Boolean(pu.enabled),
        provider: pu.provider || "ntfy",
        min_severity: pu.min_severity || "critical",
        ntfy_url: pu.ntfy_url || "https://ntfy.sh",
        ntfy_topic: pu.ntfy_topic || "",
        ntfy_token: "",
        telegram_bot_token: "",
        telegram_chat_id: pu.telegram_chat_id || "",
        gotify_url: pu.gotify_url || "",
        gotify_token: "",
      };

      const ce = out.customer_email_routing || {};
      this.form.customer_email_routing = {
        enabled: Boolean(ce.enabled),
        min_severity: ce.min_severity || "critical",
        send_resolved:
          ce.send_resolved !== undefined ? Boolean(ce.send_resolved) : true,
      };

      if (Array.isArray(out.rule_packs) && out.rule_packs.length) {
        this.rulePacks = out.rule_packs.map((p) => ({
          pack_id: p.pack_id,
          filename: p.filename,
          enabled: Boolean(p.enabled),
          rules_count: p.rules_count || 0,
        }));
      }
    },
    buildConfigureAlertingPayload() {
      const toAddresses = String(this.form.defaultToAddressesText || "")
        .split(/[\n,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);

      const smtpPort = parseInt(this.form.smarthost_email.smtp_port, 10) || 587;

      return {
        group_wait: this.form.group_wait || "30s",
        group_interval: this.form.group_interval || "5m",
        repeat_interval: this.form.repeat_interval || "4h",
        smarthost_email: {
          enabled: Boolean(this.form.smarthost_email.enabled),
          use_ns8_smarthost: Boolean(
            this.form.smarthost_email.use_ns8_smarthost
          ),
          smtp_host: this.form.smarthost_email.smtp_host || "",
          smtp_port: smtpPort,
          smtp_user: this.form.smarthost_email.smtp_user || "",
          smtp_password: this.form.smarthost_email.smtp_password || "",
          smtp_password_unchanged: Boolean(
            this.secretFlags.has_smtp_password &&
              !this.form.smarthost_email.smtp_password
          ),
          smtp_tls: Boolean(this.form.smarthost_email.smtp_tls),
          from_address: this.form.smarthost_email.from_address || "",
          default_to_addresses: toAddresses,
          send_resolved: Boolean(this.form.smarthost_email.send_resolved),
        },
        webhook_psa: {
          enabled: Boolean(this.form.webhook_psa.enabled),
          url: this.form.webhook_psa.url || "",
          auth_secret: this.form.webhook_psa.auth_secret || "",
          auth_secret_unchanged: Boolean(
            this.secretFlags.has_auth_secret &&
              !this.form.webhook_psa.auth_secret
          ),
          send_resolved: Boolean(this.form.webhook_psa.send_resolved),
        },
        chat: {
          teams_enabled: Boolean(this.form.chat.teams_enabled),
          teams_webhook_url: this.form.chat.teams_webhook_url || "",
          teams_webhook_unchanged: Boolean(
            this.secretFlags.has_teams_webhook_url &&
              !this.form.chat.teams_webhook_url
          ),
          slack_enabled: Boolean(this.form.chat.slack_enabled),
          slack_webhook_url: this.form.chat.slack_webhook_url || "",
          slack_webhook_unchanged: Boolean(
            this.secretFlags.has_slack_webhook_url &&
              !this.form.chat.slack_webhook_url
          ),
          slack_channel: this.form.chat.slack_channel || "",
          send_resolved: Boolean(this.form.chat.send_resolved),
        },
        push: {
          enabled: Boolean(this.form.push.enabled),
          provider: this.form.push.provider || "none",
          min_severity: this.form.push.min_severity || "critical",
          ntfy_url: this.form.push.ntfy_url || "https://ntfy.sh",
          ntfy_topic: this.form.push.ntfy_topic || "",
          ntfy_token: this.form.push.ntfy_token || "",
          ntfy_token_unchanged: Boolean(
            this.secretFlags.has_ntfy_token && !this.form.push.ntfy_token
          ),
          telegram_bot_token: this.form.push.telegram_bot_token || "",
          telegram_bot_token_unchanged: Boolean(
            this.secretFlags.has_telegram_bot_token &&
              !this.form.push.telegram_bot_token
          ),
          telegram_chat_id: this.form.push.telegram_chat_id || "",
          gotify_url: this.form.push.gotify_url || "",
          gotify_token: this.form.push.gotify_token || "",
          gotify_token_unchanged: Boolean(
            this.secretFlags.has_gotify_token && !this.form.push.gotify_token
          ),
        },
        customer_email_routing: {
          enabled: Boolean(this.form.customer_email_routing.enabled),
          min_severity:
            this.form.customer_email_routing.min_severity || "critical",
          send_resolved: Boolean(
            this.form.customer_email_routing.send_resolved
          ),
        },
        enabled_rule_packs: this.rulePacks
          .filter((p) => p.enabled)
          .map((p) => p.pack_id),
      };
    },
    async submitConfigureAlerting() {
      this.validationErrors = {};
      this.savingAlerting = true;
      const payload = this.buildConfigureAlertingPayload();
      const taskAction = "configure-alerting";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.configureAlertingAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.configureAlertingValidationFailed
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.configureAlertingCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.configure-alerting"),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.savingAlerting = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    configureAlertingAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.savingAlerting = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.save_failed")
      );
    },
    configureAlertingValidationFailed(validationErrors) {
      this.savingAlerting = false;
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
    configureAlertingCompleted() {
      this.savingAlerting = false;
      this.feedbackBanner = {
        kind: "success",
        title: this.$t("alerting.saved_title"),
        description: this.$t("alerting.saved_description"),
      };
      this.loadAlerting();
    },
    openTestAlertModal() {
      this.testAlertForm = {
        channel: "all",
        customer: this.tenants.length ? this.tenants[0].customer : "",
      };
      this.showTestModal = true;
    },
    async submitTestAlert() {
      this.sendingTestAlert = true;
      const payload = {
        channel: this.testAlertForm.channel,
        customer:
          this.testAlertForm.channel === "customer_email"
            ? this.testAlertForm.customer || ""
            : "",
      };
      const taskAction = "test-alert";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.testAlertAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.testAlertCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.test-alert"),
            description: payload.channel,
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.sendingTestAlert = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    testAlertAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.sendingTestAlert = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.test_alert_failed")
      );
    },
    testAlertCompleted(taskContext, taskResult) {
      this.sendingTestAlert = false;
      this.showTestModal = false;
      const out = (taskResult && taskResult.output) || {};
      this.feedbackBanner = {
        kind: out.delivered ? "success" : "warning",
        title: out.delivered
          ? this.$t("alerting.test_alert_sent")
          : this.$t("alerting.test_alert_failed"),
        description: out.message || "",
      };
    },
    async loadSilences() {
      this.loadingSilences = true;
      const taskAction = "list-silences";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.loadSilencesAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.loadSilencesCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            customer: this.silenceFilter.customer || "",
            include_expired: Boolean(this.silenceFilter.include_expired),
          },
          extra: {
            title: this.$t("action.list-silences"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.loadingSilences = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    loadSilencesAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.loadingSilences = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.cannot_load_silences")
      );
    },
    loadSilencesCompleted(taskContext, taskResult) {
      this.loadingSilences = false;
      const out = (taskResult && taskResult.output) || {};
      this.silences = Array.isArray(out.silences) ? out.silences : [];
    },
    openCreateSilenceModal() {
      this.silenceErrors = {};
      this.silenceForm = {
        customer: "*",
        site: "",
        device_role: "",
        durationPreset: "2h",
        starts_at: "",
        ends_at: "",
        extraMatchersText: "",
        created_by: "msp-admin",
        comment: "",
      };
      this.applyDurationPreset();
      this.showSilenceModal = true;
    },
    onSilenceCustomerChange() {
      if (this.silenceForm.customer === "*") {
        this.silenceForm.site = "";
      }
    },
    applyDurationPreset() {
      const hoursMap = { "1h": 1, "2h": 2, "4h": 4, "8h": 8, "24h": 24 };
      const hours = hoursMap[this.silenceForm.durationPreset];
      if (!hours) {
        return;
      }
      const now = new Date();
      now.setMilliseconds(0);
      const end = new Date(now.getTime() + hours * 3600 * 1000);
      this.silenceForm.starts_at = now.toISOString().replace(".000Z", "Z");
      this.silenceForm.ends_at = end.toISOString().replace(".000Z", "Z");
    },
    parseExtraMatchers(raw) {
      const tokens = String(raw || "")
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const matchers = [];
      for (const tok of tokens) {
        const match = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*(!~|=~|!=|=)\s*(.+)$/.exec(
          tok
        );
        if (!match) {
          return null;
        }
        const op = match[2];
        const cleanVal = match[3].replace(/^["']|["']$/g, "");
        matchers.push({
          name: match[1],
          value: cleanVal,
          is_regex: op === "=~" || op === "!~",
          is_equal: op === "=" || op === "=~",
        });
      }
      return matchers;
    },
    async submitCreateSilence() {
      const errors = {};
      const startMs = Date.parse(this.silenceForm.starts_at);
      const endMs = Date.parse(this.silenceForm.ends_at);
      if (isNaN(startMs)) {
        errors.starts_at = this.$t("alerting.validation_starts_at");
      }
      if (isNaN(endMs) || endMs <= startMs) {
        errors.ends_at = this.$t("alerting.validation_ends_at");
      }
      if (!this.silenceForm.created_by.trim()) {
        errors.created_by = this.$t("alerting.validation_created_by");
      }
      if (this.silenceForm.comment.trim().length < 3) {
        errors.comment = this.$t("alerting.validation_comment");
      }
      const extraMatchers = this.parseExtraMatchers(
        this.silenceForm.extraMatchersText
      );
      if (extraMatchers === null) {
        errors.extra_matchers = this.$t("alerting.validation_extra_matchers");
      }
      this.silenceErrors = errors;
      if (Object.keys(errors).length > 0) {
        return;
      }

      this.creatingSilence = true;
      const payload = {
        customer: this.silenceForm.customer || "*",
        site:
          this.silenceForm.customer === "*"
            ? ""
            : this.silenceForm.site || "",
        device_role: this.silenceForm.device_role || "",
        extra_matchers: extraMatchers,
        starts_at: this.silenceForm.starts_at.trim(),
        ends_at: this.silenceForm.ends_at.trim(),
        created_by: this.silenceForm.created_by.trim(),
        comment: this.silenceForm.comment.trim(),
      };

      const taskAction = "create-silence";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.createSilenceAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.createSilenceCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action.create-silence"),
            description: payload.comment,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.creatingSilence = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    createSilenceAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.creatingSilence = false;
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.create_silence_failed")
      );
    },
    createSilenceCompleted() {
      this.creatingSilence = false;
      this.showSilenceModal = false;
      this.feedbackBanner = {
        kind: "success",
        title: this.$t("alerting.silence_created_title"),
        description: this.$t("alerting.silence_created_desc"),
      };
      this.loadSilences();
    },
    async expireSilence(row) {
      const taskAction = "delete-silence";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.expireSilenceAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.expireSilenceCompleted
      );

      const res = await this.to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            silence_id: row.id,
          },
          extra: {
            title: this.$t("action.delete-silence"),
            description: row.comment,
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
    expireSilenceAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.createErrorNotificationForApp(
        taskError,
        this.$t("alerting.expire_silence_failed")
      );
    },
    expireSilenceCompleted() {
      this.feedbackBanner = {
        kind: "info",
        title: this.$t("alerting.silence_expired_title"),
        description: this.$t("alerting.silence_expired_desc"),
      };
      this.loadSilences();
    },
  },
};
</script>
