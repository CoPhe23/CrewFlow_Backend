const admin = require("firebase-admin");
const path = require("path");

const serviceAccountPath = path.join(__dirname, "../../secrets/serviceAccountKey.json");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountPath),
  });
}

const db = admin.firestore();

module.exports = { admin, db };