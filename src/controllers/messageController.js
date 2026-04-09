const { db } = require("../lib/firebase");
const crypto = require("crypto");

function generateJoinCode() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

exports.createEvent = async (req, res) => {
  try {
    const { name, description } = req.body;
    const userId = req.user.userId;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Event name required" });
    }

    let joinCode;
    let exists = true;

    while (exists) {
      joinCode = generateJoinCode();

      const snap = await db
        .collection("events")
        .where("joinCode", "==", joinCode)
        .limit(1)
        .get();

      exists = !snap.empty;
    }

    const eventRef = db.collection("events").doc();
    const eventId = eventRef.id;

    await eventRef.set({
      id: eventId,
      name: name.trim(),
      description: description?.trim() || "",
      joinCode,
      createdBy: userId,
      createdAt: new Date().toISOString(),
    });

    await db.collection("event_members").add({
      eventId,
      userId,
      role: "ADMIN",
      joinedAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: "Event created successfully",
      event: {
        id: eventId,
        name: name.trim(),
        description: description?.trim() || "",
        joinCode,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Create event failed" });
  }
};

exports.joinEvent = async (req, res) => {
  try {
    const { joinCode } = req.body;
    const userId = req.user.userId;

    if (!joinCode || !joinCode.trim()) {
      return res.status(400).json({ error: "Join code required" });
    }

    const eventSnap = await db
      .collection("events")
      .where("joinCode", "==", joinCode.trim().toUpperCase())
      .limit(1)
      .get();

    if (eventSnap.empty) {
      return res.status(404).json({ error: "Invalid join code" });
    }

    const event = eventSnap.docs[0].data();

    const memberSnap = await db
      .collection("event_members")
      .where("eventId", "==", event.id)
      .where("userId", "==", userId)
      .limit(1)
      .get();

    if (!memberSnap.empty) {
      return res.status(409).json({ error: "You are already a member of this event" });
    }

    await db.collection("event_members").add({
      eventId: event.id,
      userId,
      role: "MEMBER",
      joinedAt: new Date().toISOString(),
    });

    return res.json({
      message: "Joined successfully",
      eventId: event.id,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Join failed" });
  }
};

exports.getMyEvents = async (req, res) => {
  try {
    const userId = req.user.userId;

    const membershipSnap = await db
      .collection("event_members")
      .where("userId", "==", userId)
      .get();

    const memberships = membershipSnap.docs.map((doc) => doc.data());
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

    return res.json(events);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Fetch events failed" });
  }
};

exports.getEventById = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membershipSnap = await db
      .collection("event_members")
      .where("eventId", "==", eventId)
      .where("userId", "==", userId)
      .limit(1)
      .get();

    if (membershipSnap.empty) {
      return res.status(403).json({ error: "You are not a member of this event" });
    }

    const membership = membershipSnap.docs[0].data();

    const eventDoc = await db.collection("events").doc(eventId).get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: "Event not found" });
    }

    const eventData = eventDoc.data();

    const membersSnap = await db
      .collection("event_members")
      .where("eventId", "==", eventId)
      .get();

    return res.json({
      id: eventData.id,
      name: eventData.name,
      description: eventData.description || "",
      joinCode: eventData.joinCode,
      createdBy: eventData.createdBy,
      createdAt: eventData.createdAt,
      role: membership.role,
      membersCount: membersSnap.size,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Fetch event failed" });
  }
};