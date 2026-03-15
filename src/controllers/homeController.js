const { db } = require("../lib/firebase");

exports.getHomepageData = async (req, res) => {
  try {
    const userId = req.user.userId;

    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const userData = userDoc.data();

    const membershipSnap = await db
      .collection("event_members")
      .where("userId", "==", userId)
      .get();

    const memberships = membershipSnap.docs.map(doc => doc.data());

    const events = [];

    for (const member of memberships) {
      const eventDoc = await db.collection("events").doc(member.eventId).get();

      if (eventDoc.exists) {
        const eventData = eventDoc.data();

        events.push({
          id: eventData.id,
          name: eventData.name,
          description: eventData.description || "",
          joinCode: eventData.joinCode,
          createdBy: eventData.createdBy,
          createdAt: eventData.createdAt,
          role: member.role,
        });
      }
    }

    return res.json({
      user: {
        id: userData.id,
        name: userData.name,
        email: userData.email,
      },
      events,
      eventsCount: events.length,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Homepage data load failed" });
  }
};