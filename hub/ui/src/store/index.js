import Vue from "vue";
import Vuex from "vuex";

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    instanceName: "",
    instanceLabel: "",
    core: null,
    appName: "Central Monitoring Hub",
    isAppConfigured: true,
    grafanaUrl: "",
  },
  getters: {
    instanceName: (state) => state.instanceName,
    instanceLabel: (state) => state.instanceLabel,
    core: (state) => state.core,
    isAppConfigured: (state) => state.isAppConfigured,
    grafanaUrl: (state) => state.grafanaUrl,
  },
  mutations: {
    setInstanceName(state, instanceName) {
      state.instanceName = instanceName;
    },
    setInstanceLabel(state, instanceLabel) {
      state.instanceLabel = instanceLabel;
    },
    setCore(state, core) {
      state.core = core;
    },
    setAppConfigured(state, value) {
      state.isAppConfigured = Boolean(value);
    },
    setGrafanaUrl(state, url) {
      state.grafanaUrl = url || "";
    },
  },
  actions: {
    setInstanceNameInStore({ commit }, instanceName) {
      commit("setInstanceName", instanceName);
    },
    setInstanceLabelInStore({ commit }, instanceLabel) {
      commit("setInstanceLabel", instanceLabel);
    },
    setCoreInStore({ commit }, core) {
      commit("setCore", core);
    },
    setAppConfiguredInStore({ commit }, value) {
      commit("setAppConfigured", value);
    },
    setGrafanaUrlInStore({ commit }, url) {
      commit("setGrafanaUrl", url);
    },
  },
});
