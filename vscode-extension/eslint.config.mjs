// eslint.config.mjs
import tseslint from "typescript-eslint";

export default tseslint.config(
    {
        files: ["src/**/*.ts"],
        extends: [tseslint.configs.recommended],
        rules: {
            semi: "error",
            "prefer-const": "error",
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/no-unused-vars": [
                "error",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
        },
    },
    {
        ignores: ["out/**", "node_modules/**"],
    },
);