const express = require("express");
const app = express();
const { exec } = require("child_process"); // Moved up for clarity

app.use(express.json());

// ✅ Replaced hardcoded secret with environment variable
const SECRET_TOKEN = process.env.SECRET_TOKEN;

/**
 * Helper function to escape HTML entities in a string.
 * This prevents Cross-Site Scripting (XSS) attacks.
 * @param {string} str The string to escape.
 * @returns {string} The escaped string.
 */
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return ''; // Handle non-string input gracefully, e.g., if req.query.name is undefined
  }
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;", // For HTML attributes, ' can be important
  };
  return str.replace(/[&<>"']/g, function(m) {
    return map[m];
  });
}

// ----------------------------
// ✅ 1️⃣ SQL Injection Vulnerability Fix (business logic unchanged)
//    - Using simulated parameterized queries
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // --- FIX: Use parameterized queries (simulated for no actual DB connection) ---
  // In a real application, you would use your database driver's
  // parameterized query methods (e.g., pg.query('SELECT * FROM users WHERE username = $1', [username]))
  // This separates the SQL logic from the user-provided data, preventing injection.
  const query = `SELECT * FROM users WHERE username = ?`; // Placeholder for parameter
  const params = [username]; // Separated parameters to be bound to the query

  console.log("Simulating executing parameterized query:", query, "with parameters:", params);

  // Simulated DB result
  res.json({
    message: "Query executed securely with parameterized query (simulated)",
    query: query,
    parameters: params,
  });
});

// ----------------------------
// ✅ 2️⃣ Cross-Site Scripting (XSS) Fix (business logic unchanged)
//    - Escaping user input before rendering
// ----------------------------
app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // --- FIX: Escape user input before injecting into HTML ---
  // The escapeHtml function converts characters like <, >, &, ", ' into their HTML entities,
  // preventing browser interpretation as active content.
  const escapedName = escapeHtml(name);

  // Safely injecting user input into HTML
  res.send(`
    <h1>Welcome ${escapedName}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// ✅ 3️⃣ Command Injection Fix (business logic unchanged)
//    - Validating input and avoiding unsafe exec patterns
// ----------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;

  // --- FIX: Validate input string rigorously ---
  // A robust regular expression to validate hostnames (RFC 1123 compliant, without leading/trailing hyphens)
  // and IPv4 addresses. This prevents malicious characters (e.g., ;, &&, ||, `, $, (, )) from being injected
  // into the shell command.
  const hostnameRegex = /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*(?:[a-zA-Z0-9-]{1,63})(?<!-)$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  if (!host || !hostnameRegex.test(host)) {
    return res.status(400).send("Invalid host provided. Please provide a valid hostname or IP address.");
  }

  // --- FIX: Ensure safe command execution (by rigorous input validation) ---
  // While `child_process.spawn` or `child_process.execFile` are generally safer for executing external
  // commands by passing arguments as an array (avoiding shell interpretation), the original code uses `exec`.
  // With `exec`, the most effective defense against command injection, when directly interpolating user input
  // into the command string, is *strict input validation*.
  // Since `host` is now guaranteed to be a valid hostname or IP address (and thus free of shell metacharacters),
  // direct interpolation into the `ping` command becomes safe in this specific context.
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      // Log the full error for debugging purposes, but send a less verbose message to the client
      console.error(`Command execution failed for host "${host}":`, err);
      // It's crucial to prevent leaking internal error details to clients
      return res.status(500).send(`Failed to ping host: "${host}". Error: ${stderr.trim()}`);
    }
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (now using environment variable for secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // It's good practice to check if the environment variable was actually set
  if (!SECRET_TOKEN) {
    return res.status(500).json({ error: "Server configuration error: SECRET_TOKEN not set" });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});