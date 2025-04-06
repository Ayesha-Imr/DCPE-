export default {
  testEnvironment: "node",
  verbose: true,
  collectCoverage: true,
  coverageDirectory: "coverage",
  moduleFileExtensions: ["js", "mjs"],
  rootDir: "./",
  transform: {
    "^.+\\.m?js$": "babel-jest", 
  },
  transformIgnorePatterns: [], 
  testMatch: ["**/dcpe/**/*.test.mjs"], 
};