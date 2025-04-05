export default {
  testEnvironment: "node",
  verbose: true,
  collectCoverage: true,
  coverageDirectory: "coverage",
  moduleFileExtensions: ["js", "mjs"],
  rootDir: "./dcpe",
  transform: {
    "^.+\\.m?js$": "babel-jest", 
  },
  transformIgnorePatterns: [], 
  testMatch: ["<rootDir>/**/*.test.mjs"], 
};