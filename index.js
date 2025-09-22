import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Set up EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Static files middleware (if needed for CSS/JS files)
app.use(express.static(path.join(__dirname, 'public')));

// Route to serve the dashboard
app.get("/", async(req, res) => {
    try {
        res.render("home");
    } catch (error) {
        console.error("Error rendering home page:", error);
        res.status(500).send("Error loading dashboard");
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({ status: "OK", timestamp: new Date().toISOString() });
});

app.listen(3000, async() => {
    console.log("🚀 DevXploit Dashboard running on http://localhost:3000");
    console.log("📊 Access your security intelligence dashboard at the URL above");
})