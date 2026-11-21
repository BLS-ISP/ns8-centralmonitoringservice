export default {
  name: "LottieAnimation",
  props: {
    animationData: { type: [Object, String], default: null },
    loop: { type: [Boolean, Number], default: false },
    autoPlay: { type: Boolean, default: true },
    speed: { type: Number, default: 1 },
    width: { type: Number, default: -1 },
    height: { type: Number, default: -1 },
  },
  render(h) {
    return h("div", {
      class: "ns-lottie-placeholder",
      attrs: { "aria-hidden": "true" },
    });
  },
};
