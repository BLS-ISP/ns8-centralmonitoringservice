<template>
  <div class="app-side-menu-content">
    <div class="instance-name">
      <div v-if="instanceLabel">{{ instanceLabel }}</div>
      <div v-else-if="instanceName">{{ instanceName }}</div>
      <cv-skeleton-text v-else :width="'70%'" />
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'status')"
        :active="isLinkActive('status')"
      >
        <template v-slot:nav-icon>
          <Analytics20 />
        </template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'tenants')"
        :active="isLinkActive('tenants')"
      >
        <template v-slot:nav-icon>
          <Enterprise20 />
        </template>
        <span>{{ $t("tenants.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'targets')"
        :active="isLinkActive('targets')"
      >
        <template v-slot:nav-icon>
          <Network_320 />
        </template>
        <span>{{ $t("targets.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'alerting')"
        :active="isLinkActive('alerting')"
      >
        <template v-slot:nav-icon>
          <Notification20 />
        </template>
        <span>{{ $t("alerting.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'settings')"
        :active="isLinkActive('settings')"
      >
        <template v-slot:nav-icon>
          <Settings20 />
        </template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'about')"
        :active="isLinkActive('about')"
      >
        <template v-slot:nav-icon>
          <Information20 />
        </template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { QueryParamService, UtilService } from "@nethserver/ns8-ui-lib";
import Analytics20 from "@carbon/icons-vue/es/analytics/20";
import Enterprise20 from "@carbon/icons-vue/es/enterprise/20";
import Network_320 from "@carbon/icons-vue/es/network--3/20";
import Notification20 from "@carbon/icons-vue/es/notification/20";
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";

export default {
  name: "AppSideMenuContent",
  components: {
    Analytics20,
    Enterprise20,
    Network_320,
    Notification20,
    Settings20,
    Information20,
  },
  mixins: [QueryParamService, UtilService],
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  methods: {
    isLinkActive(page) {
      return this.getPage() === page || this.$route.path === `/${page}`;
    },
    goToAppPage(instanceName, page) {
      if (this.core && this.core.$router && instanceName) {
        this.core.$router.push(`/apps/${instanceName}?page=${page}`);
      }
      if (this.$route.path !== `/${page}`) {
        this.$router.push(`/${page}`);
      }
      this.$root.$emit("closeSideMenu");
    },
  },
};
</script>

