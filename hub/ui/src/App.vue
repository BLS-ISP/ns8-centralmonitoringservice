<template>
  <div id="ns8-app">
    <cv-content id="main-content" class="app-main-content">
      <AppSideMenuContent class="desktop-side-menu" />
      <AppMobileSideMenu />
      <div class="app-router-view">
        <NsInlineNotification
          v-if="!isAppConfigured && $route.name !== 'Settings'"
          kind="warning"
          :title="$t('settings.unconfigured_title')"
          :description="$t('settings.unconfigured_description')"
          :actionLabel="$t('settings.configure_instance_btn')"
          @action="goToSettings"
          :showCloseButton="false"
          class="mg-bottom-md"
        />
        <router-view />
      </div>
    </cv-content>
  </div>
</template>

<script>
import {
  TaskService,
  QueryParamService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { mapState, mapActions } from "vuex";
import AppSideMenuContent from "./components/AppSideMenuContent.vue";
import AppMobileSideMenu from "./components/AppMobileSideMenu.vue";

export default {
  name: "App",
  components: {
    AppSideMenuContent,
    AppMobileSideMenu,
  },
  mixins: [TaskService, QueryParamService, UtilService],
  computed: {
    ...mapState(["instanceName", "core", "isAppConfigured"]),
  },
  created() {
    const core = window.parent && window.parent.core ? window.parent.core : null;
    this.setCoreInStore(core);

    if (core && core.$root) {
      core.$root.$on("ToggleSideMenu", this.onToggleMobileSideMenu);
    }

    const instanceName = this.extractInstanceName();
    this.setInstanceNameInStore(instanceName);

    this.syncLocaleFromCore(core);
    this.syncRouteWithQueryParams();

    if (core && instanceName) {
      this.retrieveModuleInfo();
    }
  },
  beforeDestroy() {
    if (this.core && this.core.$root) {
      this.core.$root.$off("ToggleSideMenu", this.onToggleMobileSideMenu);
    }
  },
  methods: {
    ...mapActions([
      "setInstanceNameInStore",
      "setInstanceLabelInStore",
      "setCoreInStore",
    ]),
    extractInstanceName() {
      if (window.parent && window.parent.location && window.parent.location.hash) {
        const match = /#\/apps\/([a-zA-Z0-9_-]+)/.exec(
          window.parent.location.hash
        );
        if (match && match[1]) {
          return match[1];
        }
      }
      return "central-monitoring-hub1";
    },
    syncLocaleFromCore(core) {
      try {
        if (core && core.$i18n && core.$i18n.locale) {
          const lang = core.$i18n.locale.substring(0, 2).toLowerCase();
          if (lang === "de" || lang === "en") {
            this.$i18n.locale = lang;
          }
        }
      } catch (e) {
        // Fallback to default VueI18n locale ("en" / "de")
      }
    },
    syncRouteWithQueryParams() {
      const requestedPage = this.getPage();
      const validPages = [
        "status",
        "tenants",
        "targets",
        "alerting",
        "settings",
        "about",
      ];
      if (requestedPage && validPages.includes(requestedPage)) {
        if (this.$route.path !== `/${requestedPage}`) {
          this.$router.replace(`/${requestedPage}`);
        }
      }
    },
    onToggleMobileSideMenu() {
      this.$root.$emit("toggleMobileSideMenu");
    },
    async retrieveModuleInfo() {
      const taskAction = "list-installed-modules";
      const eventId = this.getUuid();

      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-aborted-${eventId}`,
        this.retrieveModuleInfoAborted
      );
      (this.core && this.core.$root ? this.core.$root : this.$root).$once(
        `${taskAction}-completed-${eventId}`,
        this.retrieveModuleInfoCompleted
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
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task")
        );
      }
    },
    retrieveModuleInfoAborted(taskError, taskContext) {
      console.error(`${taskContext.action} aborted`, taskError);
      this.createErrorNotificationForApp(
        taskError,
        this.$t("error.cannot_retrieve_installed_modules")
      );
    },
    retrieveModuleInfoCompleted(taskContext, taskResult) {
      const output = taskResult && taskResult.output ? taskResult.output : {};
      let foundModule = null;
      Object.values(output).forEach((moduleList) => {
        if (Array.isArray(moduleList)) {
          moduleList.forEach((mod) => {
            if (mod && mod.id === this.instanceName) {
              foundModule = mod;
            }
          });
        }
      });
      if (foundModule) {
        this.setInstanceLabelInStore(foundModule.ui_name || "");
      }
    },
    goToSettings() {
      if (this.$route.path !== "/settings") {
        this.$router.push("/settings");
      }
    },
  },
};
</script>

