export default {
  name: "LottieAnimation",
  props: {
    animationData: {
      type: [Object, String],
      default: null,
    },
    loop: {
      type: [Boolean, Number],
      default: false,
    },
    autoPlay: {
      type: Boolean,
      default: true,
    },
  },
  render(h) {
    return h("div", { class: "ns-lottie-placeholder", attrs: { "aria-hidden": "true" } });
  },
};
