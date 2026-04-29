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

exports.createPost = async (req, res) => {
  try {
    const { eventId, text } = req.body;
    const userId = req.user.userId;

    if (!eventId || !text || !text.trim()) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Not a member" });
    }

    if (membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Only admins can post" });
    }

    const userDoc = await db.collection("users").doc(userId).get();
    const user = userDoc.exists ? userDoc.data() : null;

    const postRef = db.collection("posts").doc();

    await postRef.set({
      id: postRef.id,
      eventId,
      text: text.trim(),
      userId,
      authorName: user?.name || "Admin",
      role: membership.role,
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: "Post created",
      post: {
        id: postRef.id,
        eventId,
        text: text.trim(),
        userId,
        authorName: user?.name || "Admin",
        role: membership.role,
        createdAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Create post failed" });
  }
};

exports.getEventPosts = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Not a member" });
    }

    const snap = await db.collection("posts").where("eventId", "==", eventId).get();

    const posts = snap.docs
      .map((doc) => doc.data())
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return res.json({ posts });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Fetch posts failed" });
  }
};

exports.deletePost = async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.user.userId;

    const postDoc = await db.collection("posts").doc(postId).get();

    if (!postDoc.exists) {
      return res.status(404).json({ error: "Post not found" });
    }

    const post = postDoc.data();

    const membership = await getMembership(post.eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Only admins can delete posts" });
    }

    await db.collection("posts").doc(postId).delete();

    return res.json({ message: "Post deleted" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Delete post failed" });
  }
};