const express = require("express");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        status: "online",
        service: "EIK Verification System"
    });
});

app.post("/verify", async (req, res) => {
    try {
        const captchaToken = req.body["g-recaptcha-response"];

        if (!captchaToken) {
            return res.status(400).json({
                success: false,
                error: "CAPTCHA fehlt."
            });
        }

        if (!RECAPTCHA_SECRET) {
            console.error("RECAPTCHA_SECRET fehlt.");

            return res.status(500).json({
                success: false,
                error: "Server-Konfiguration fehlt."
            });
        }

        const response = await fetch(
            "https://www.google.com/recaptcha/api/siteverify",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({
                    secret: RECAPTCHA_SECRET,
                    response: captchaToken
                })
            }
        );

        const result = await response.json();

        console.log("reCAPTCHA result:", result);

        if (!result.success) {
            return res.status(403).json({
                success: false,
                error: "CAPTCHA-Verifizierung fehlgeschlagen."
            });
        }

        return res.json({
            success: true,
            message: "CAPTCHA erfolgreich verifiziert."
        });

    } catch (error) {
        console.error("Verification error:", error);

        return res.status(500).json({
            success: false,
            error: "Interner Serverfehler."
        });
    }
});

app.listen(PORT, () => {
    console.log(`EIK Verification System läuft auf Port ${PORT}`);
});
