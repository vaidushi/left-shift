const fs = require("fs");
const { execSync } = require("child_process");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });

async function getChangedFiles() {
  const output = execSync(
    "git diff --name-only HEAD^ HEAD"
  ).toString();

  return output
  .split("\n")
  .filter(file => file.endsWith(".js"));
}

async function secureFile(filePath) {
  const code = fs.readFileSync(filePath, "utf8");

  const prompt = `
You are a senior security engineer.

Your tasks:
1. Detect security vulnerabilities (hardcoded secrets, injection, insecure comparisons).
2. Fix them properly using best practices.
3. Replace secrets with environment variables.
4. Ensure the code is fully runnable.
5. Return ONLY the corrected raw JavaScript code.
6. No explanations. No markdown.

Code:
${code}
`;

  const result = await model.generateContent(prompt);
  const response = result.response.text();

  fs.writeFileSync(filePath, response);
  console.log(`✅ Secured: ${filePath}`);
}

async function run() {
  const files = await getChangedFiles();

  if (files.length === 0) {
    console.log("No JS files changed.");
    return;
  }

  for (const file of files) {
    await secureFile(file);
  }
}

run();
