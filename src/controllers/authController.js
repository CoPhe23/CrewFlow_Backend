const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { db } = require("../lib/firebase");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

function signToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email, password required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "password must be at least 6 chars" });
    }


    const existingSnap = await db.collection("users").where("email", "==", email).limit(1).get();
    if (!existingSnap.empty) return res.status(409).json({ error: "Email already in use" });

    const passwordHash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();

    await db.collection("users").doc(id).set({
      id,
      name,
      email,
      passwordHash,
      createdAt: new Date().toISOString(),
    });

    const user = { id, name, email };
    const token = signToken(id);

    return res.status(201).json({ user, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email, password required" });
    }

    const snap = await db.collection("users").where("email", "==", email).limit(1).get();
    if (snap.empty) return res.status(401).json({ error: "Invalid credentials" });

    const doc = snap.docs[0];
    const data = doc.data();

    const ok = await bcrypt.compare(password, data.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const user = { id: data.id, name: data.name, email: data.email };
    const token = signToken(user.id);

    return res.json({ user, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};

exports.me = async (req, res) => {
  try {
    const userId = req.user.userId;

    const doc = await db.collection("users").doc(userId).get();
    if (!doc.exists) return res.status(404).json({ error: "User not found" });

    const data = doc.data();
    return res.json({ user: { id: data.id, name: data.name, email: data.email } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: "email required" });
    }

    const snap = await db
      .collection("users")
      .where("email", "==", email)
      .limit(1)
      .get();

    return res.json({
      message:
        "Ha létezik ilyen email cím, elküldtük a jelszó visszaállítási útmutatót.",
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: "email required" });
    }

    const snap = await db
      .collection("users")
      .where("email", "==", email)
      .limit(1)
      .get();

    // Biztonság miatt akkor is sikeres üzenetet adunk, ha nincs ilyen email
    if (snap.empty) {
      return res.json({
        message:
          "Ha létezik ilyen email cím, elküldtük a visszaállítási linket.",
      });
    }

    const doc = snap.docs[0];
    const user = doc.data();

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = Date.now() + 1000 * 60 * 15; // 15 perc

    await db.collection("users").doc(user.id).update({
      resetToken,
      resetTokenExpires,
    });

    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"CrewFlow" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "CrewFlow jelszó visszaállítás",
      html: `
            <h2>CrewFlow</h2>
            <p>Jelszó visszaállításhoz kattints:</p>
            <a href="${resetLink}">Jelszó módosítása</a>
            `
    });

    return res.json({
      message:
        "Ha létezik ilyen email cím, elküldtük a visszaállítási linket.",
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body || {};

    if (!token || !password) {
      return res.status(400).json({ error: "token and password required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "password must be at least 6 chars" });
    }

    const snap = await db
      .collection("users")
      .where("resetToken", "==", token)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const doc = snap.docs[0];
    const user = doc.data();

    if (!user.resetTokenExpires || user.resetTokenExpires < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await db.collection("users").doc(user.id).update({
      passwordHash,
      resetToken: null,
      resetTokenExpires: null,
    });

    return res.json({ message: "Jelszó sikeresen módosítva." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
};