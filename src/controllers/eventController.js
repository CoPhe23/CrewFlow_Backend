const crypto = require("crypto");
const { db } = require("../lib/firebase");

function generateJoinCode() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

async function getMembership(eventId, userId) {
  const snap = await db
    .collection("event_members")
    .where("eventId", "==", eventId)
    .where("userId", "==", userId)
    .limit(1)
    .get();

  if (snap.empty) return null;

  return {
    id: snap.docs[0].id,
    ...snap.docs[0].data(),
  };
}

async function deleteCollectionByEventId(collectionName, eventId) {
  const snap = await db.collection(collectionName).where("eventId", "==", eventId).get();

  const batch = db.batch();

  snap.docs.forEach((doc) => {
    batch.delete(doc.ref);
  });

  await batch.commit();
}

exports.createEvent = async (req, res) => {
  try {
    const { name, description } = req.body;
    const userId = req.user.userId;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Add meg az esemény nevét." });
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

    const event = {
      id: eventId,
      name: name.trim(),
      description: description?.trim() || "",
      joinCode,
      createdBy: userId,
      createdAt: new Date().toISOString(),
    };

    await eventRef.set(event);

    await db.collection("event_members").add({
      eventId,
      userId,
      role: "ADMIN",
      joinedAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: "Esemény létrehozva.",
      event: {
        ...event,
        role: "ADMIN",
        membersCount: 1,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült létrehozni az eseményt." });
  }
};

exports.joinEvent = async (req, res) => {
  try {
    const { joinCode } = req.body;
    const userId = req.user.userId;

    if (!joinCode || !joinCode.trim()) {
      return res.status(400).json({ error: "Add meg az esemény kódját." });
    }

    const eventSnap = await db
      .collection("events")
      .where("joinCode", "==", joinCode.trim().toUpperCase())
      .limit(1)
      .get();

    if (eventSnap.empty) {
      return res.status(404).json({ error: "Érvénytelen eseménykód." });
    }

    const event = eventSnap.docs[0].data();

    const memberSnap = await db
      .collection("event_members")
      .where("eventId", "==", event.id)
      .where("userId", "==", userId)
      .limit(1)
      .get();

    if (!memberSnap.empty) {
      return res.status(409).json({ error: "Már tagja vagy ennek az eseménynek." });
    }

    await db.collection("event_members").add({
      eventId: event.id,
      userId,
      role: "MEMBER",
      joinedAt: new Date().toISOString(),
    });

    return res.json({
      message: "Sikeres csatlakozás.",
      eventId: event.id,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült csatlakozni." });
  }
};

exports.getMyEvents = async (req, res) => {
  try {
    const userId = req.user.userId;

    const membershipSnap = await db
      .collection("event_members")
      .where("userId", "==", userId)
      .get();

    const events = [];

    for (const memberDoc of membershipSnap.docs) {
      const member = memberDoc.data();

      const eventDoc = await db.collection("events").doc(member.eventId).get();

      if (!eventDoc.exists) continue;

      const eventData = eventDoc.data();

      const membersSnap = await db
        .collection("event_members")
        .where("eventId", "==", eventData.id)
        .get();

      events.push({
        id: eventData.id,
        name: eventData.name,
        description: eventData.description || "",
        joinCode: eventData.joinCode,
        createdBy: eventData.createdBy,
        createdAt: eventData.createdAt,
        role: member.role,
        membersCount: membersSnap.size,
      });
    }

    return res.json(events);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült betölteni az eseményeket." });
  }
};

exports.getEventById = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(403).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    const eventDoc = await db.collection("events").doc(eventId).get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: "Az esemény nem található." });
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
    return res.status(500).json({ error: "Nem sikerült betölteni az eseményt." });
  }
};

exports.updateEvent = async (req, res) => {
  try {
    const { eventId } = req.params;
    const { name, description } = req.body;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin szerkesztheti az eseményt." });
    }

    const eventDoc = await db.collection("events").doc(eventId).get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: "Az esemény nem található." });
    }

    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Az esemény neve kötelező." });
    }

    await db.collection("events").doc(eventId).update({
      name: name.trim(),
      description: description?.trim() || "",
      updatedAt: new Date().toISOString(),
    });

    return res.json({ message: "Esemény frissítve." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült frissíteni az eseményt." });
  }
};

exports.leaveEvent = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership) {
      return res.status(404).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    if (membership.role === "ADMIN") {
      const adminsSnap = await db
        .collection("event_members")
        .where("eventId", "==", eventId)
        .where("role", "==", "ADMIN")
        .get();

      if (adminsSnap.size <= 1) {
        return res.status(400).json({
          error: "Utolsó adminként nem léphetsz ki. Előbb adj admin jogot másnak, vagy töröld az eseményt.",
        });
      }
    }

    await db.collection("event_members").doc(membership.id).delete();

    return res.json({ message: "Sikeresen kiléptél az eseményből." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült kilépni az eseményből." });
  }
};

exports.deleteEvent = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;

    const membership = await getMembership(eventId, userId);

    if (!membership || membership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin törölheti az eseményt." });
    }

    const eventDoc = await db.collection("events").doc(eventId).get();

    if (!eventDoc.exists) {
      return res.status(404).json({ error: "Az esemény nem található." });
    }

    await deleteCollectionByEventId("event_members", eventId);
    await deleteCollectionByEventId("tasks", eventId);
    await deleteCollectionByEventId("messages", eventId);
    await deleteCollectionByEventId("posts", eventId);

    await db.collection("events").doc(eventId).delete();

    return res.json({ message: "Esemény törölve." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült törölni az eseményt." });
  }
};

exports.getEventMembers = async (req, res) => {
  try {
    const { eventId } = req.params;
    const currentUserId = req.user.userId;

    const myMembership = await getMembership(eventId, currentUserId);

    if (!myMembership) {
      return res.status(403).json({ error: "Nem vagy tagja ennek az eseménynek." });
    }

    const membershipSnap = await db
      .collection("event_members")
      .where("eventId", "==", eventId)
      .get();

    const members = [];

    for (const doc of membershipSnap.docs) {
      const member = doc.data();

      let userName = "Felhasználó";
      let userEmail = "";

      const userDoc = await db.collection("users").doc(member.userId).get();

      if (userDoc.exists) {
        const user = userDoc.data();
        userName = user.name || user.email || "Felhasználó";
        userEmail = user.email || "";
      }

      members.push({
        membershipId: doc.id,
        userId: member.userId,
        role: member.role,
        name: userName,
        email: userEmail,
        joinedAt: member.joinedAt,
        isMe: member.userId === currentUserId,
      });
    }

    return res.json({ members });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Nem sikerült betölteni a résztvevőket." });
  }
};

exports.promoteMember = async (req, res) => {
  try {
    const { eventId, userId: targetUserId } = req.params;
    const currentUserId = req.user.userId;

    const myMembership = await getMembership(eventId, currentUserId);

    if (!myMembership || myMembership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin adhat admin jogot." });
    }

    const targetMembership = await getMembership(eventId, targetUserId);

    if (!targetMembership) {
      return res.status(404).json({ error: "A felhasználó nem található az eseményben." });
    }

    await db.collection("event_members").doc(targetMembership.id).update({
      role: "ADMIN",
    });

    return res.json({ message: "Admin jog megadva." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült adminná tenni." });
  }
};

exports.removeMember = async (req, res) => {
  try {
    const { eventId, userId: targetUserId } = req.params;
    const currentUserId = req.user.userId;

    const myMembership = await getMembership(eventId, currentUserId);

    if (!myMembership || myMembership.role !== "ADMIN") {
      return res.status(403).json({ error: "Csak admin távolíthat el tagot." });
    }

    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: "Saját magadat nem távolíthatod el itt. Használd a kilépést." });
    }

    const targetMembership = await getMembership(eventId, targetUserId);

    if (!targetMembership) {
      return res.status(404).json({ error: "A tag nem található." });
    }

    await db.collection("event_members").doc(targetMembership.id).delete();

    return res.json({ message: "Tag eltávolítva." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Nem sikerült eltávolítani a tagot." });
  }
};