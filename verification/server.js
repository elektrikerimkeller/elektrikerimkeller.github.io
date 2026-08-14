const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI =
    process.env.DISCORD_REDIRECT_URI ||
    "https://eik-verification.onrender.com/callback";

const BOT_VERIFICATION_API_URL =
    process.env.BOT_VERIFICATION_API_URL;

const VERIFICATION_API_KEY =
    process.env.VERIFICATION_API_KEY;




const GUILD_CONFIG = [
    {
        name: "#Team Elektrikerimkeller Community",
        guildId: "1096885316452884582",
        roleId: "1537784947304304730"
    },

    {
        name: "Elektriker Im Keller Roblox Advantages",
        guildId: "1330840221037756437",
        roleId: "1537785385046778008"
    },

    {
        name: "Elektriker Im Keller HANGOUT",
        guildId: "1330840221037756437",
        roleId: "1537785604207677460"
    },

    {
        name: "Tropical Event Studios",
        guildId: "1301212226346160148",
        roleId: "1396463431376437308"
    },

    {
        name: "Elektrik Studios",
        guildId: "1100801948107681802",
        roleId: "1537786067716014120"
    },

    {
        name: "Elektriker's Testserver",
        guildId: "1073286667982606508",
        roleId: "1537786271177379950"
    }
];




const sessions = new Map();

const SESSION_TIME = 10 * 60 * 1000;

function createSession(data = {}) {

    const id = crypto.randomBytes(32).toString("hex");

    sessions.set(id, {
        ...data,
        createdAt: Date.now()
    });

    return id;
}

function getSession(id) {

    if (!id) {
        return null;
    }

    const session = sessions.get(id);

    if (!session) {
        return null;
    }

    if (Date.now() - session.createdAt > SESSION_TIME) {
        sessions.delete(id);
        return null;
    }

    return session;
}




const cooldowns = new Map();

const COOLDOWN_MS = 60 * 1000;

function getCooldownKey(userId, guildId, roleId) {
    return `${userId}:${guildId}:${roleId}`;
}

function getRemainingCooldown(userId, guildId, roleId) {

    const key = getCooldownKey(
        userId,
        guildId,
        roleId
    );

    const lastVerification = cooldowns.get(key);

    if (!lastVerification) {
        return 0;
    }

    const remaining =
        COOLDOWN_MS -
        (Date.now() - lastVerification);

    if (remaining <= 0) {
        cooldowns.delete(key);
        return 0;
    }

    return remaining;
}




app.use(cors());

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(express.json());




function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}




app.get("/", (req, res) => {

    res.json({
        status: "online",
        service: "EIK Verification System"
    });

});




app.post("/verify", async (req, res) => {

    try {

        const captchaToken =
            req.body["g-recaptcha-response"];

        if (!captchaToken) {

            return res.status(400).json({
                success: false,
                error: "CAPTCHA fehlt."
            });

        }

        if (!RECAPTCHA_SECRET) {

            console.error(
                "RECAPTCHA_SECRET fehlt."
            );

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
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    secret: RECAPTCHA_SECRET,
                    response: captchaToken
                })
            }
        );

        const result =
            await response.json();

        console.log(
            "reCAPTCHA result:",
            result
        );

        if (!result.success) {

            return res.status(403).json({
                success: false,
                error:
                    "CAPTCHA-Verifizierung fehlgeschlagen."
            });

        }




        const sessionId =
            createSession({
                captchaVerified: true
            });


        res.cookie(
            "eik_verification",
            sessionId,
            {
                httpOnly: true,
                secure: true,
                sameSite: "lax",
                maxAge: SESSION_TIME
            }
        );




        if (
            !DISCORD_CLIENT_ID ||
            !DISCORD_CLIENT_SECRET
        ) {

            return res.status(500).send(
                "Discord OAuth2 ist noch nicht konfiguriert."
            );

        }

        const state =
            crypto.randomBytes(32).toString("hex");

        const session =
            getSession(sessionId);

        session.oauthState = state;


        const params =
            new URLSearchParams({

                client_id:
                    DISCORD_CLIENT_ID,

                response_type:
                    "code",

                redirect_uri:
                    DISCORD_REDIRECT_URI,

                scope:
                    "identify guilds",

                state

            });


        return res.redirect(
            `https://discord.com/oauth2/authorize?${params.toString()}`
        );


    } catch (error) {

        console.error(
            "Verification error:",
            error
        );

        return res.status(500).json({
            success: false,
            error: "Interner Serverfehler."
        });

    }

});




app.get("/callback", async (req, res) => {

    try {

        const {
            code,
            state
        } = req.query;

        if (!code || !state) {

            return res.status(400).send(
                "Ungültige Discord-Anfrage."
            );

        }


        const sessionId =
            req.headers.cookie
                ?.split(";")
                .map(x => x.trim())
                .find(x =>
                    x.startsWith(
                        "eik_verification="
                    )
                )
                ?.split("=")[1];


        const session =
            getSession(sessionId);


        if (!session) {

            return res.status(400).send(
                "Verifizierungssitzung abgelaufen. Bitte erneut starten."
            );

        }


        if (
            !session.oauthState ||
            session.oauthState !== state
        ) {

            return res.status(403).send(
                "Ungültiger OAuth2-State."
            );

        }




        const tokenResponse =
            await fetch(
                "https://discord.com/api/oauth2/token",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    },

                    body: new URLSearchParams({

                        client_id:
                            DISCORD_CLIENT_ID,

                        client_secret:
                            DISCORD_CLIENT_SECRET,

                        grant_type:
                            "authorization_code",

                        code,

                        redirect_uri:
                            DISCORD_REDIRECT_URI

                    })
                }
            );


        const tokenData =
            await tokenResponse.json();


        if (
            !tokenResponse.ok ||
            !tokenData.access_token
        ) {

            console.error(
                "Discord Token Fehler:",
                tokenData
            );

            return res.status(401).send(
                "Discord-Anmeldung konnte nicht abgeschlossen werden."
            );

        }


        const accessToken =
            tokenData.access_token;




        const userResponse =
            await fetch(
                "https://discord.com/api/users/@me",
                {
                    headers: {
                        Authorization:
                            `Bearer ${accessToken}`
                    }
                }
            );


        const user =
            await userResponse.json();


        if (!userResponse.ok) {

            return res.status(401).send(
                "Discord-Benutzer konnte nicht abgerufen werden."
            );

        }




        const guildResponse =
            await fetch(
                "https://discord.com/api/users/@me/guilds",
                {
                    headers: {
                        Authorization:
                            `Bearer ${accessToken}`
                    }
                }
            );


        const userGuilds =
            await guildResponse.json();


        if (!guildResponse.ok) {

            return res.status(401).send(
                "Discord-Server konnten nicht abgerufen werden."
            );

        }




        session.user = user;

        session.guilds =
            userGuilds;

        session.accessToken =
            accessToken;

        session.oauthState =
            null;




        const availableGuilds =
            GUILD_CONFIG.filter(config =>

                userGuilds.some(
                    guild =>
                        guild.id ===
                        config.guildId
                )

            );


        return res.send(
            renderGuildSelection(
                user,
                availableGuilds
            )
        );


    } catch (error) {

        console.error(
            "OAuth callback error:",
            error
        );

        return res.status(500).send(
            "Interner Serverfehler."
        );

    }

});




function renderGuildSelection(
    user,
    guilds
) {

    const options =
        guilds.map(
            (guild, index) => `

                <label class="guild-card">

                    <input
                        type="radio"
                        name="selection"
                        value="${index}"
                        required
                    >

                    <div>

                        <strong>
                            ${escapeHtml(guild.name)}
                        </strong>

                        <small>
                            Discord-Verifizierung
                        </small>

                    </div>

                </label>

            `
        ).join("");


    if (!guilds.length) {

        return `
<!DOCTYPE html>
<html lang="de">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>EIK System – Keine Server</title>

<style>

body {
    margin: 0;
    min-height: 100vh;
    background: #080c17;
    color: white;
    font-family: Arial, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
}

.card {
    width: min(500px, calc(100% - 40px));
    padding: 35px;
    background: #0f172a;
    border: 1px solid rgba(255,255,255,.1);
    border-radius: 24px;
    text-align: center;
}

p {
    color: #94a3b8;
}

</style>

</head>

<body>

<div class="card">

<h1>Keine Server verfügbar</h1>

<p>
Für deinen Discord-Account wurde kein
konfigurierter Server gefunden.
</p>

</div>

</body>

</html>
        `;

    }


    return `
<!DOCTYPE html>
<html lang="de">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>EIK System – Discord Verifizierung</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at 20% 10%,
            rgba(59,130,246,.15),
            transparent 35%
        ),
        #080c17;

    color: white;

    font-family:
        Arial,
        sans-serif;

    display: flex;

    align-items: center;

    justify-content: center;

    padding: 20px;

}

.card {

    width: min(
        600px,
        100%
    );

    background:
        rgba(
            15,
            23,
            42,
            .9
        );

    border:
        1px solid
        rgba(
            255,
            255,
            255,
            .1
        );

    border-radius: 28px;

    padding: 32px;

    box-shadow:
        0 25px 80px
        rgba(0,0,0,.45);

}

.badge {

    display: inline-block;

    color: #60a5fa;

    font-size: 13px;

    margin-bottom: 10px;

}

h1 {

    margin:
        0 0 10px;

}

.description {

    color: #94a3b8;

    margin-bottom: 25px;

}

.guilds {

    display: flex;

    flex-direction: column;

    gap: 12px;

}

.guild-card {

    display: flex;

    align-items: center;

    gap: 15px;

    padding: 18px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius: 16px;

    background:
        rgba(255,255,255,.03);

    cursor: pointer;

    transition: .2s;

}

.guild-card:hover {

    background:
        rgba(59,130,246,.08);

    border-color:
        rgba(59,130,246,.3);

}

.guild-card input {

    width: 18px;

    height: 18px;

}

.guild-card strong {

    display: block;

}

.guild-card small {

    display: block;

    margin-top: 5px;

    color: #64748b;

}

button {

    width: 100%;

    margin-top: 25px;

    padding: 15px;

    border: 0;

    border-radius: 14px;

    background: #2563eb;

    color: white;

    font-size: 16px;

    font-weight: bold;

    cursor: pointer;

}

button:hover {

    background: #3b82f6;

}

.user {

    color: #60a5fa;

}

</style>

</head>

<body>

<div class="card">

<div class="badge">
EIK SYSTEM • VERIFIZIERUNG
</div>

<h1>
Discord-Verifizierung
</h1>

<p class="description">

Willkommen
<span class="user">
${escapeHtml(user.username)}
</span>!

<br><br>

Wähle den Discord-Server,
für den du dich verifizieren möchtest.

</p>

<form method="POST"
      action="/verify/guild">

<div class="guilds">

${options}

</div>

<input
    type="hidden"
    name="count"
    value="${guilds.length}"
>

<button type="submit">
🛡️ Jetzt verifizieren
</button>

</form>

</div>

</body>

</html>
    `;

}




app.post(
    "/verify/guild",
    async (req, res) => {

        try {

            const sessionId =
                req.headers.cookie
                    ?.split(";")
                    .map(x => x.trim())
                    .find(x =>
                        x.startsWith(
                            "eik_verification="
                        )
                    )
                    ?.split("=")[1];


            const session =
                getSession(sessionId);


            if (
                !session ||
                !session.user ||
                !session.guilds
            ) {

                return res.status(401).send(
                    "Deine Sitzung ist abgelaufen. Bitte erneut verifizieren."
                );

            }


            const selection =
                Number(req.body.selection);


            const availableGuilds =
                GUILD_CONFIG.filter(config =>

                    session.guilds.some(
                        guild =>
                            guild.id ===
                            config.guildId
                    )

                );


            if (
                !Number.isInteger(selection) ||
                selection < 0 ||
                selection >= availableGuilds.length
            ) {

                return res.status(400).send(
                    "Ungültige Serverauswahl."
                );

            }


            const selected =
                availableGuilds[selection];




            const remaining =
                getRemainingCooldown(
                    session.user.id,
                    selected.guildId,
                    selected.roleId
                );


            if (remaining > 0) {

                const seconds =
                    Math.ceil(
                        remaining / 1000
                    );

                return res.status(429).send(
                    renderMessage(
                        "⏳ Bitte warten",
                        `Du hast dich für diesen Server gerade erst verifiziert. Bitte warte noch ${seconds} Sekunden.`
                    )
                );

            }




            if (
                !BOT_VERIFICATION_API_URL ||
                !VERIFICATION_API_KEY
            ) {

                console.error(
                    "Bot Verification API nicht konfiguriert."
                );

                return res.status(500).send(
                    "Die Verification-API ist noch nicht vollständig konfiguriert."
                );

            }


            /*
            ============================================
            BOT ANSPRECHEN
            ============================================
            */

            const botResponse =
                await fetch(
                    `${BOT_VERIFICATION_API_URL}/verification/role`,
                    {

                        method: "POST",

                        headers: {

                            "Content-Type":
                                "application/json",

                            "Authorization":
                                `Bearer ${VERIFICATION_API_KEY}`

                        },

                        body:
                            JSON.stringify({

                                user_id:
                                    session.user.id,

                                guild_id:
                                    selected.guildId,

                                role_id:
                                    selected.roleId

                            })

                    }
                );


            const botResult =
                await botResponse.json();


            console.log(
                "Bot Verification Result:",
                botResult
            );


            if (!botResponse.ok) {

                return res.status(
                    botResponse.status
                ).send(

                    renderMessage(
                        "❌ Verifizierung fehlgeschlagen",
                        botResult.error ||
                        "Die Discord-Rolle konnte nicht vergeben werden."
                    )

                );

            }




            const cooldownKey =
                getCooldownKey(
                    session.user.id,
                    selected.guildId,
                    selected.roleId
                );

            cooldowns.set(
                cooldownKey,
                Date.now()
            );




            return res.send(

                renderSuccess(
                    session.user.username,
                    selected.name,
                    Boolean(
                        botResult.already_verified
                    )
                )

            );


        } catch (error) {

            console.error(
                "Guild verification error:",
                error
            );

            return res.status(500).send(

                renderMessage(
                    "❌ Fehler",
                    "Bei der Verifizierung ist ein interner Fehler aufgetreten."
                )

            );

        }

    }
);




function renderSuccess(
    username,
    guildName,
    alreadyVerified
) {

    const title =
        alreadyVerified
            ? "Bereits verifiziert"
            : "Du wurdest erfolgreich verifiziert!";


    const text =
        alreadyVerified
            ? "Du besitzt die erforderliche Rolle bereits."
            : "Die Discord-Rolle wurde erfolgreich vergeben.";


    return `

<!DOCTYPE html>

<html lang="de">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>EIK System – Erfolgreich</title>

<style>

body {

    margin: 0;

    min-height: 100vh;

    background: #080c17;

    color: white;

    font-family: Arial, sans-serif;

    display: flex;

    align-items: center;

    justify-content: center;

}

.card {

    width: min(
        550px,
        calc(100% - 40px)
    );

    padding: 40px;

    text-align: center;

    background: #0f172a;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius: 28px;

    box-shadow:
        0 25px 80px
        rgba(0,0,0,.5);

}

.icon {

    font-size: 60px;

    margin-bottom: 20px;

}

h1 {

    color: #4ade80;

}

p {

    color: #94a3b8;

    line-height: 1.7;

}

.server {

    color: #60a5fa;

    font-weight: bold;

}

</style>

</head>

<body>

<div class="card">

<div class="icon">
✅
</div>

<h1>
${escapeHtml(title)}
</h1>

<p>

Hallo
<strong>
${escapeHtml(username)}
</strong>!

<br><br>

${escapeHtml(text)}

<br><br>

Server:

<span class="server">
${escapeHtml(guildName)}
</span>

</p>

</div>

</body>

</html>

    `;

}




function renderMessage(
    title,
    message
) {

    return `

<!DOCTYPE html>

<html lang="de">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>EIK System</title>

<style>

body {

    margin: 0;

    min-height: 100vh;

    background: #080c17;

    color: white;

    font-family: Arial, sans-serif;

    display: flex;

    align-items: center;

    justify-content: center;

}

.card {

    width: min(
        550px,
        calc(100% - 40px)
    );

    padding: 40px;

    text-align: center;

    background: #0f172a;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius: 28px;

}

h1 {

    color: #f87171;

}

p {

    color: #94a3b8;

    line-height: 1.7;

}

</style>

</head>

<body>

<div class="card">

<h1>
${escapeHtml(title)}
</h1>

<p>
${escapeHtml(message)}
</p>

</div>

</body>

</html>

    `;

}




app.listen(
    PORT,
    () => {

        console.log(
            `EIK Verification System läuft auf Port ${PORT}`
        );

    }
);
