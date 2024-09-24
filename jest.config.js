module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    testPathIgnorePatterns: ["<rootDir>/dist/", "<rootDir>/node_modules/"],
    moduleFileExtensions: ["ts", "js", "json", "node"],
    testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.ts$",
    transform: {
        "^.+\\.ts$": "ts-jest",
    },
};
