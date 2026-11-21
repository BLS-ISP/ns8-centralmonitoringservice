const path = require("path");
const { defineConfig } = require("@vue/cli-service");

module.exports = defineConfig({
  publicPath: "./",
  productionSourceMap: false,
  configureWebpack: {
    performance: {
      hints: false,
    },
    resolve: {
      alias: {
        "lottie-web-vue": path.resolve(__dirname, "src/shims/lottie-shim.js"),
      },
      fallback: {
        crypto: path.resolve(__dirname, "src/shims/crypto-shim.js"),
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
  chainWebpack: (config) => {
    config.optimization.minimizer("terser").tap((args) => {
      args[0].terserOptions.keep_classnames = true;
      args[0].terserOptions.keep_fnames = true;
      return args;
    });
  },
});
