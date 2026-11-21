<template>
  <transition name="slide-menu">
    <div
      v-if="isMenuShown"
      class="mobile-side-menu"
      role="navigation"
      :aria-label="$t('common.navigation')"
    >
      <AppSideMenuContent />
    </div>
  </transition>
</template>

<script>
import AppSideMenuContent from "./AppSideMenuContent.vue";

export default {
  name: "AppMobileSideMenu",
  components: {
    AppSideMenuContent,
  },
  data() {
    return {
      isMenuShown: false,
    };
  },
  created() {
    this.$root.$on("toggleMobileSideMenu", this.toggleMobileSideMenu);
    this.$root.$on("closeSideMenu", this.closeSideMenu);
  },
  beforeDestroy() {
    this.$root.$off("toggleMobileSideMenu", this.toggleMobileSideMenu);
    this.$root.$off("closeSideMenu", this.closeSideMenu);
  },
  methods: {
    toggleMobileSideMenu() {
      this.isMenuShown = !this.isMenuShown;
    },
    closeSideMenu() {
      this.isMenuShown = false;
    },
  },
};
</script>

