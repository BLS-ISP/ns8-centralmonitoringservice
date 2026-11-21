<template>
  <div class="bx--grid bx--grid--full-width bx--no-gutter">
    <div class="collector-page-header">
      <div>
        <h1 class="collector-page-title">{{ $t("about.title") }}</h1>
        <p class="collector-page-subtitle">{{ $t("about.description") }}</p>
      </div>
    </div>

    <div class="bx--row">
      <div class="bx--col-lg-10 bx--col-md-8 bx--col-sm-4" style="margin-bottom: 1rem">
        <section class="collector-card" aria-labelledby="arch-capabilities-heading">
          <h2 id="arch-capabilities-heading" class="collector-card-title">
            {{ $t("about.architecture_title") }}
          </h2>
          <ul class="capability-list">
            <li>{{ $t("about.feature_zero_wan") }}</li>
            <li>{{ $t("about.feature_local_ns8") }}</li>
            <li>{{ $t("about.feature_lan_discovery") }}</li>
            <li>{{ $t("about.feature_wal_resilience") }}</li>
          </ul>
        </section>
      </div>

      <div class="bx--col-lg-6 bx--col-md-8 bx--col-sm-4" style="margin-bottom: 1rem">
        <section class="collector-card" aria-labelledby="meta-heading">
          <h2 id="meta-heading" class="collector-card-title">
            {{ appMetadata.name }}
          </h2>
          <div class="collector-kv-list">
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("about.version") }}</span>
              <span class="collector-kv-value">{{ appMetadata.version }}</span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("about.license") }}</span>
              <span class="collector-kv-value">{{ appMetadata.license }}</span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("about.documentation") }}</span>
              <span class="collector-kv-value">
                <a
                  :href="appMetadata.docs.documentation_url"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="external-link"
                >
                  <span>NethServer 8 Docs</span>
                  <Launch20 class="inline-launch-icon" />
                </a>
              </span>
            </div>
            <div class="collector-kv-row">
              <span class="collector-kv-label">{{ $t("about.source_code") }}</span>
              <span class="collector-kv-value">
                <a
                  :href="appMetadata.docs.code_url"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="external-link"
                >
                  <span>GitHub</span>
                  <Launch20 class="inline-launch-icon" />
                </a>
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script>
import Launch20 from "@carbon/icons-vue/es/launch/20";
import appConfig from "../../public/config.json";

export default {
  name: "About",
  components: {
    Launch20,
  },
  data() {
    return {
      appMetadata: appConfig,
    };
  },
};
</script>

