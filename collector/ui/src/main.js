import Vue from "vue";
import VueI18n from "vue-i18n";
import axios from "axios";
import CarbonComponentsVue from "@carbon/vue";
import ns8Lib, { Filters, StorageService } from "@nethserver/ns8-ui-lib";
import "carbon-components/css/carbon-components.min.css";
import "./styles/collector.css";

import App from "./App.vue";
import router from "./router";
import store from "./store";
import enMessages from "../public/i18n/en/translation.json";
import deMessages from "../public/i18n/de/translation.json";

Vue.config.productionTip = false;
Vue.use(CarbonComponentsVue);
Vue.use(ns8Lib);
Vue.use(VueI18n);
if (StorageService) {
  Vue.mixin(StorageService);
}

if (Filters) {
  Object.keys(Filters).forEach((filterName) => {
    Vue.filter(filterName, Filters[filterName]);
  });
}

Vue.prototype.axios = axios;

function detectInitialLocale() {
  try {
    const parentLang =
      (window.parent &&
        window.parent.localStorage &&
        window.parent.localStorage.getItem("lang")) ||
      navigator.language ||
      "en";
    const shortLang = String(parentLang).slice(0, 2).toLowerCase();
    return shortLang === "de" ? "de" : "en";
  } catch (_err) {
    return "en";
  }
}

const i18n = new VueI18n({
  locale: detectInitialLocale(),
  fallbackLocale: "en",
  silentTranslationWarn: true,
  messages: {
    en: enMessages,
    de: deMessages,
  },
});

window.ns8CollectorApp = new Vue({
  router,
  store,
  i18n,
  render: (h) => h(App),
}).$mount("#app");
