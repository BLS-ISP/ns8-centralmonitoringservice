<template>
  <div class="ns-page-content">
    <div class="page-toolbar">
      <h1>{{ $t("about.title") }}</h1>
    </div>

    <section class="section-card">
      <div class="section-card__header">
        <div>
          <h2 class="section-card__title">{{ appConfig.name }}</h2>
          <p class="section-card__subtitle">{{ localizedDescription }}</p>
        </div>
        <NsTag kind="blue" :label="`v${appConfig.version}`" />
      </div>

      <div class="form-grid-2">
        <div>
          <h3 class="form-section-title">{{ $t("about.module_details") }}</h3>
          <p class="mg-bottom-sm">
            <strong>{{ $t("about.instance") }}:</strong>
            <span class="mono-text">{{ instanceName || "-" }}</span>
          </p>
          <p class="mg-bottom-sm">
            <strong>{{ $t("about.oci_source") }}:</strong>
            <span class="mono-text">{{ appConfig.source }}</span>
          </p>
          <p class="mg-bottom-sm">
            <strong>{{ $t("about.categories") }}:</strong>
            {{ (appConfig.categories || []).join(", ") }}
          </p>
          <p
            v-if="appConfig.authors && appConfig.authors.length"
            class="mg-bottom-sm"
          >
            <strong>{{ $t("about.authors") }}:</strong>
            <span v-for="(author, idx) in appConfig.authors" :key="idx">
              {{ author.name }} ({{ author.email }})
            </span>
          </p>
        </div>

        <div>
          <h3 class="form-section-title">{{ $t("about.resources") }}</h3>
          <p class="mg-bottom-sm" v-if="appConfig.docs.documentation_url">
            <cv-link
              :href="appConfig.docs.documentation_url"
              target="_blank"
              rel="noopener noreferrer"
            >
              {{ $t("about.documentation") }}
              <Launch20 />
            </cv-link>
          </p>
          <p class="mg-bottom-sm" v-if="appConfig.docs.code_url">
            <cv-link
              :href="appConfig.docs.code_url"
              target="_blank"
              rel="noopener noreferrer"
            >
              {{ $t("about.source_code") }}
              <Launch20 />
            </cv-link>
          </p>
          <p class="mg-bottom-sm" v-if="appConfig.docs.bug_url">
            <cv-link
              :href="appConfig.docs.bug_url"
              target="_blank"
              rel="noopener noreferrer"
            >
              {{ $t("about.report_issue") }}
              <Launch20 />
            </cv-link>
          </p>
        </div>
      </div>
    </section>
  </div>
</template>

<script>
import { mapState } from "vuex";
import { PageTitleService } from "@nethserver/ns8-ui-lib";
import Launch20 from "@carbon/icons-vue/es/launch/20";
import appConfig from "../../public/config.json";

export default {
  name: "About",
  components: {
    Launch20,
  },
  mixins: [PageTitleService],
  pageTitle() {
    return `${this.$t("about.title")} - ${this.appName}`;
  },
  data() {
    return {
      appConfig,
    };
  },
  computed: {
    ...mapState(["instanceName", "appName"]),
    localizedDescription() {
      const desc = this.appConfig && this.appConfig.description;
      if (!desc) {
        return "";
      }
      if (typeof desc === "string") {
        return desc;
      }
      return desc[this.$i18n.locale] || desc.en || "";
    },
  },
};
</script>
