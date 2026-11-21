import Vue from "vue";
import App from "./App.vue";
import router from "./router";
import store from "./store";
import VueI18n from "vue-i18n";
import CarbonVue from "@carbon/vue";
import ns8Lib, { Filters } from "@nethserver/ns8-ui-lib";
import VueDateFns from "vue-date-fns";
import axios from "axios";

import "carbon-components/css/carbon-components.min.css";
import "./styles/_core.scss";

import enMessages from "../public/i18n/en/translation.json";
import deMessages from "../public/i18n/de/translation.json";

Vue.config.productionTip = false;

Vue.use(CarbonVue);
Vue.use(ns8Lib);
Vue.use(VueI18n);
Vue.use(VueDateFns);

Object.keys(Filters).forEach((filterName) => {
  Vue.filter(filterName, Filters[filterName]);
});

Vue.prototype.axios = axios;

const navigatorLang =
  typeof navigator !== "undefined" && navigator.language
    ? navigator.language.substring(0, 2).toLowerCase()
    : "en";

const initialLocale = navigatorLang === "de" ? "de" : "en";

const i18n = new VueI18n({
  locale: initialLocale,
  fallbackLocale: "en",
  silentTranslationWarn: true,
  messages: {
    en: enMessages,
    de: deMessages,
  },
});

new Vue({
  router,
  store,
  i18n,
  render: (h) => h(App),
}).$mount("#app");
