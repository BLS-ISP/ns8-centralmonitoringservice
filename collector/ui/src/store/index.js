import Vue from "vue";
import Vuex from "vuex";

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    instanceName: "",
    instanceLabel: "",
    core: null,
  },
  mutations: {
    setInstanceNameInStore(state, name) {
      state.instanceName = name;
    },
    setInstanceLabelInStore(state, label) {
      state.instanceLabel = label;
    },
    setCoreInStore(state, core) {
      state.core = core;
    },
  },
  actions: {
    setInstanceName({ commit }, name) {
      commit("setInstanceNameInStore", name);
    },
    setInstanceLabel({ commit }, label) {
      commit("setInstanceLabelInStore", label);
    },
    setCore({ commit }, core) {
      commit("setCoreInStore", core);
    },
  },
});
