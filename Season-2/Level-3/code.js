// Welcome to Secure Code Game Season-2/Level-3!

// Follow the instructions below to get started:

// 1. test.js is passing but the code here is vulnerable
// 2. Review the code. Can you spot the bugs(s)?
// 3. Fix the code.js but ensure that test.js passes
// 4. Run hack.js and if passing then CONGRATS!
// 5. If stuck then read the hint
// 6. Compare your solution with solution.js

const express = require("express");
const bodyParser = require("body-parser");
const sax = require("sax");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const sanitizeFilename = require("sanitize-filename");
const { execFile } = require("node:child_process");
const shellQuote = require("shell-quote");
const app = express();

// Define and ensure upload directory exists
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

app.use(bodyParser.json());
app.use(bodyParser.text({ type: "application/xml" }));

const storage = multer.memoryStorage();
const upload = multer({ storage });

app.post("/ufo/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  console.log("Received uploaded file:", req.file.originalname);

  // Sanitize filename
  const safeFilename = sanitizeFilename(req.file.originalname);
  const uploadedFilePath = path.resolve(UPLOAD_DIR, safeFilename);
  // Ensure the file is within the upload directory
  if (!uploadedFilePath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).send("Invalid file path.");
  }
  fs.writeFileSync(uploadedFilePath, req.file.buffer);

  res.status(200).send("File uploaded successfully.");
});

app.post("/ufo", (req, res) => {
  const contentType = req.headers["content-type"];

  if (contentType === "application/json") {
    console.log("Received JSON data:", req.body);
    res.status(200).json({ ufo: "Received JSON data from an unknown planet." });
  } else if (contentType === "application/xml") {
    try {
      // Use sax to parse XML safely (no entity expansion)
      const extractedContent = [];
      let isAdmin = false;
      let currentText = "";
      const parser = sax.parser(true, { lowercase: true });

      parser.onopentag = function (node) {
        // Check for admin tag
        if (node.name && node.name.toLowerCase() === "admin") {
          isAdmin = true;
        }
      };

      parser.ontext = function (text) {
        currentText += text;
      };

      parser.onclosetag = function (tagName) {
        // On closing a tag, push text if not empty
        if (currentText.trim().length > 0) {
          extractedContent.push(currentText.trim());
        }
        currentText = "";
      };

      parser.onerror = function (err) {
        throw err;
      };

      parser.write(req.body).close();

      // Secret feature to allow an "admin" to execute commands
      if (isAdmin) {
        // Only allow certain commands for security
        const ALLOWED_COMMANDS = ["ls", "cat", "echo"];
        extractedContent.forEach((commandStr) => {
          // Parse command string safely
          const parsed = shellQuote.parse(commandStr);
          if (!Array.isArray(parsed) || parsed.length === 0) {
            res.status(400).send("Invalid command");
            return;
          }
          const cmd = parsed[0];
          const args = parsed.slice(1);
          if (!ALLOWED_COMMANDS.includes(cmd)) {
            res.status(403).send("Command not allowed");
            return;
          }
          execFile(cmd, args, (err, output) => {
            if (err) {
              console.error("could not execute command: ", err);
              res.status(500).send("Command execution failed");
              return;
            }
            console.log("Output: \n", output);
            res.status(200).set("Content-Type", "text/plain").send(output);
          });
        });
      } else {
        res
          .status(200)
          .set("Content-Type", "text/plain")
          .send(extractedContent.join(" "));
      }
    } catch (error) {
      console.error("XML parsing or validation error:", error.message);
      res.status(400).send("Invalid XML: " + error.message);
    }
  } else {
    res.status(405).send("Unsupported content type");
  }
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = server;