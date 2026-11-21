<template>
  <div id="ns8-collector-root" class="collector-shell">
    <cv-header aria-label="Central Monitoring Collector navigation">
      <cv-header-name prefix="NS8">
        {{ instanceLabel || instanceName || "central-monitoring-collector1" }}
      </cv-header-name>
      <cv-header-nav aria-label="Collector sections">
        <cv-header-menu-item to="/status" :active="$route.path === '/status'">
          {{ $t("nav.status") }}
        </cv-header-menu-item>
        <cv-header-menu-item
          to="/local-targets"
          :active="$route.path === '/local-targets'"
        >
          {{ $t("nav.local_targets") }}
        </cv-header-menu-item>
        <cv-header-menu-item
          to="/settings"
          :active="$route.path === '/settings'"
        >
          {{ $t("nav.settings") }}
        </cv-header-menu-item>
        <cv-header-menu-item to="/about" :active="$route.path === '/about'">
          {{ $t("nav.about") }}
        </cv-header-menu-item>
      </cv-header-nav>
    </cv-header>

    <cv-content id="main-content" class="collector-main-content">
      <router-view />
    </cv-content>
  </div>
</template>

<script>
import { mapState, mapActions } from "vuex";
import { StorageService, TaskService, UtilService } from "@nethserver/ns8-ui-lib";

export default {
  name: "App",
  mixins: [TaskService, UtilService, StorageService],
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  created() {
    const coreRef = window.parent && window.parent.core ? window.parent.core : null;
    this.setCore(coreRef);

    const detectedInstance = this.extractInstanceName();
    this.setInstanceName(detectedInstance);

    if (coreRef) {
      this.syncLocaleFromCore(coreRef);
      if (coreRef.$root && coreRef.$root.apiUrl) {
        this.$root.apiUrl = coreRef.$root.apiUrl;
      }
      if (detectedInstance) {
        this.retrieveModuleInfo();
      }
    }
  },
  methods: {
    ...mapActions(["setInstanceName", "setInstanceLabel", "setCore"]),
    extractInstanceName() {
      try {
        if (
          window.parent &&
          window.parent.location &&
          window.parent.location.hash
        ) {
          const hashMatch = /#\/apps\/([a-zA-Z0-9_-]+)/.exec(
            window.parent.location.hash
          );
          if (hashMatch && hashMatch[1]) {
            return hashMatch[1];
          }
        }
      } catch (_err) {
        // Cross-origin fallback in standalone tests
      }
      const pathMatch = window.location.pathname.match(/\/apps\/([a-zA-Z0-9_-]+?[0-9]+)/);
      return pathMatch ? pathMatch[1] : "central-monitoring-collector1";
    },
    syncLocaleFromCore(coreRef) {
      try {
        if (coreRef.$i18n && coreRef.$i18n.locale) {
          const lang = String(coreRef.$i18n.locale).slice(0, 2).toLowerCase();
          if (lang === "de" || lang === "en") {
            this.$i18n.locale = lang;
          }
        }
      } catch (_err) {
        // Keep detected initial locale
      }
    },
    async retrieveModuleInfo() {
      const taskAction = "list-installed-modules";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        (taskError) => {
          this.createErrorNotificationForApp(
            taskError,
            this.$t("error.cannot_retrieve_installed_modules")
          );
        }
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        (_taskContext, taskResult) => {
          const output = taskResult && taskResult.output ? taskResult.output : {};
          Object.values(output).forEach((moduleList) => {
            if (Array.isArray(moduleList)) {
              moduleList.forEach((mod) => {
                if (mod && mod.id === this.instanceName && mod.ui_name) {
                  this.setInstanceLabel(mod.ui_name);
                }
              });
            }
          });
        }
      );

      const res = await this.to(
        this.createClusterTaskForApp({
          action: taskAction,
          extra: {
            title: this.$t("action.list-installed-modules"),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];
      if (err) {
        this.createErrorNotificationForApp(err, this.$t("task.cannot_create_task"));
      }
    },
  },
};
</script>

