const HtmlWebpackPlugin = require("html-webpack-plugin");
const path = require("path");

const git_hash = require("child_process")
  .execSync("git rev-parse HEAD")
  .toString()
  .trim();

module.exports = {
  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "..", "docs"),
    filename: "bootstrap.js",
  },
  mode: process.env.NODE_ENV || "development",
  plugins: [
    new HtmlWebpackPlugin({
      template: "index.html",
      filename: "index.html",
      templateParameters: {
        git_hash,
        short_git_hash: git_hash.slice(0, 7),
      },
    }),
  ],
  experiments: {
    asyncWebAssembly: true,
  },
};
