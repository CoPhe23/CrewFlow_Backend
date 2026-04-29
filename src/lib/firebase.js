const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");

function getServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

    if (serviceAccount.private_key) {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
    }

    return serviceAccount;
  }

  const localPath = path.join(__dirname, "../../secrets/serviceAccountKey.json");

  if (fs.existsSync(localPath)) {
    return require(localPath);
  }

  throw new Error("Missing Firebase credentials");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(getServiceAccount()),
  });
}

const db = admin.firestore();

module.exports = { admin, db };