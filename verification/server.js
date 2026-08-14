const express = require("express");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;

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
    console.log("Verification request received");

    const captchaToken = req.body["g-recaptcha-response"];

    if (!captchaToken) {
        return res.status(400).json({
            success: false,
            error: "CAPTCHA fehlt."
        });
    }

    console.log("CAPTCHA token received");

    return res.json({
        success: true,
        message: "CAPTCHA wurde empfangen."
    });
});

app.listen(PORT, () => {
    console.log(`EIK Verification System läuft auf Port ${PORT}`);
});
