const { db } = require("../lib/firebase");

async function getMembership(eventId, userId) {
  const snap = await db
    .collection("event_members")
    .where("eventId", "==", eventId)
    .where("userId", "==", userId)
    .limit(1)
    .get();

  if (snap.empty) return null;
  return snap.docs[0].data();
}

exports.sendMessage = async (req, res) => {
  try {
    const { eventId, text } = req.body;
    const userId = req.user.userId;

    if (!eventId || !text) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Not a member" });
    }

    const messageRef = db.collection("messages").doc();

    await messageRef.set({
      id: messageRef.id,
      eventId,
      text,
      userId,
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: "Message sent",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Send failed" });
  }
};

exports.getMessages = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Not a member" });
    }

    const snap = await db
      .collection("messages")
      .where("eventId", "==", eventId)
      .get();

    const messages = snap.docs
      .map((doc) => doc.data())
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

    return res.json(messages);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Fetch failed" });
  }
};