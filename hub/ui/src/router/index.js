import Vue from "vue";
import VueRouter from "vue-router";
import Status from "../views/Status.vue";
import Tenants from "../views/Tenants.vue";
import Targets from "../views/Targets.vue";
import Alerting from "../views/Alerting.vue";
import Settings from "../views/Settings.vue";
import About from "../views/About.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    redirect: "/status",
  },
  {
    path: "/status",
    name: "Status",
    component: Status,
  },
  {
    path: "/tenants",
    name: "Tenants",
    component: Tenants,
  },
  {
    path: "/targets",
    name: "Targets",
    component: Targets,
  },
  {
    path: "/alerting",
    name: "Alerting",
    component: Alerting,
  },
  {
    path: "/settings",
    name: "Settings",
    component: Settings,
  },
  {
    path: "/about",
    name: "About",
    component: About,
  },
];

const router = new VueRouter({
  mode: "hash",
  base: process.env.BASE_URL,
  routes,
});

export default router;
