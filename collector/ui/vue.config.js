const path = require("path");
const { defineConfig } = require("@vue/cli-service");

module.exports = defineConfig({
  publicPath: "./",
  productionSourceMap: false,
  transpileDependencies: ["@nethserver/ns8-ui-lib"],
  configureWebpack: {
    performance: {
      hints: false,
    },
    resolve: {
      alias: {
        "lottie-web-vue": path.resolve(__dirname, "src/shims/lottie-stub.js"),
      },
      fallback: {
        crypto: path.resolve(__dirname, "src/shims/crypto-browser.js"),
      },
    },
  },
  css: {
    loaderOptions: {
      sass: {
        sassOptions: {
          quietDeps: true,
        },
      },
    },
  },
});
